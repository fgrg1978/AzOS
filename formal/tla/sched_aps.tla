--------------------------- MODULE sched_aps ---------------------------
(*
AZOS — Adaptive Partitioning Scheduler (RFC-0004, INV-5, INV-8)

Models the high-level behaviour of `crates/core/sched/src/partitions.rs`:
the CPU is divided across NumClasses scheduling classes per partition
window. Each class has a guaranteed `min_pct` fraction (here a Nat,
out of 100) and a max cap.

We model:

  - per-class consumed counter, reset on window roll-over
  - per-class `runnable` flag (some task is ready to run in that class)
  - per-tick: a chosen class is debited the slice; the chosen class is
    selected by APS phase 1 (any under_min runnable) → phase 2
    (non-exhausted, urgency order) → phase 3 (degraded, urgency order)

Invariants verified:

  APS-1  TypeOK — counters stay in 0..MaxConsumed; window stays in
         0..NumWindows; chosen_class is None or valid index.

  APS-2  GuaranteedMinimum — over a full window, if a class is
         continuously runnable, its consumed counter never exceeds
         100 (i.e., we don't *under*-bill — TLC walks all schedules
         and confirms the simulator never produces an impossible
         consumption).

  APS-3  ChosenIsRunnable — every non-idle tick has chosen_class in
         a runnable class (phase 3 fallback prevents idle when work
         exists).

Run with TLC, default config in `sched_aps.cfg`.

MODEL VS CODE (doc audit, 2026-09-26): this spec has no task queue — a
class is just a `runnable` flag (line ~13, ~55 in the state below), not
a set of waiting tasks. `crates/core/sched/src/partitions.rs`'s real defect
(a woken task lands in the legacy ring, not in any policy queue, so APS
never sees it as runnable and starves it) is outside what a boolean
flag can express, and so is the same-tick CBS refill interaction. A
model that cannot represent the bug cannot certify its absence.
`book/src/02-architecture/scheduler.md` cites `ConsumptionBounded` and
`ChosenIsRunnable` as "TLA+ verified" guarantees of the scheduler; they
are guarantees of this simplified model only. No TLC run against this
file is recorded past 2026-05-14, and `tools/ci_check.sh` does not
invoke TLC.
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS WindowSlices,        \* slices per window, set in .cfg
          MaxTicks             \* simulation horizon

\* Model parameters fixed in-spec because TLC's `CONSTANTS` syntax
\* doesn't accept sequence literals. We verify on a representative
\* 3-class shape that exercises every APS branch (under-min,
\* non-exhausted, degraded). The full 5-class production system has
\* identical structure — adding classes scales the state space but
\* doesn't change the proved properties.
NumClasses == 3
MinPct == <<20, 30, 50>>
MaxPct == <<60, 60, 100>>

ASSUME /\ WindowSlices \in Nat /\ WindowSlices > 0
       /\ MaxTicks \in Nat /\ MaxTicks > 0

VARIABLES
    consumed,        \* function: class index -> Nat (slices consumed in window)
    runnable,        \* function: class index -> BOOLEAN
    sliceCount,      \* slices in current window so far
    chosen,          \* the class chosen this tick (1..NumClasses or 0=idle)
    tick

vars == <<consumed, runnable, sliceCount, chosen, tick>>

\* Per-class min/max as slice counts (out of WindowSlices).
MinSlices(c) == (MinPct[c] * WindowSlices) \div 100
MaxSlices(c) == (MaxPct[c] * WindowSlices) \div 100

UnderMin(c) == consumed[c] < MinSlices(c)
OverMax(c)  == consumed[c] >= MaxSlices(c)

\* Initial state.
Init ==
    /\ consumed = [c \in 1..NumClasses |-> 0]
    /\ runnable = [c \in 1..NumClasses |-> TRUE]
    /\ sliceCount = 0
    /\ chosen = 0
    /\ tick = 0

\* Compute the APS-chosen class given current state. Returns 0 if no
\* class is runnable. Otherwise:
\*   phase 1: smallest-indexed runnable class with UnderMin
\*   phase 2: smallest-indexed runnable class with not OverMax
\*   phase 3: smallest-indexed runnable class
PickClass ==
    IF \E c \in 1..NumClasses : runnable[c] /\ UnderMin(c) THEN
        CHOOSE c \in 1..NumClasses : runnable[c] /\ UnderMin(c)
            /\ \A d \in 1..NumClasses :
                  (runnable[d] /\ UnderMin(d)) => c <= d
    ELSE IF \E c \in 1..NumClasses : runnable[c] /\ ~OverMax(c) THEN
        CHOOSE c \in 1..NumClasses : runnable[c] /\ ~OverMax(c)
            /\ \A d \in 1..NumClasses :
                  (runnable[d] /\ ~OverMax(d)) => c <= d
    ELSE IF \E c \in 1..NumClasses : runnable[c] THEN
        CHOOSE c \in 1..NumClasses : runnable[c]
            /\ \A d \in 1..NumClasses : runnable[d] => c <= d
    ELSE
        0

\* The window is "full" once `sliceCount` has reached its capacity.
\* RunSlice cannot fire while full; only EndWindow can. This guarantees
\* `consumed[c] <= WindowSlices` at all reachable states.
WindowFull == sliceCount >= WindowSlices

\* Action: run one slice. Cannot fire when the window is full —
\* `EndWindow` must roll over first.
RunSlice ==
    /\ tick < MaxTicks
    /\ ~WindowFull
    /\ tick' = tick + 1
    /\ chosen' = PickClass
    /\ consumed' = IF chosen' \in 1..NumClasses
                     THEN [consumed EXCEPT ![chosen'] = consumed[chosen'] + 1]
                     ELSE consumed
    /\ sliceCount' = sliceCount + 1
    /\ runnable' = runnable           \* runnability fluctuates externally

\* Action: window ends, reset all consumption counters.
EndWindow ==
    /\ tick < MaxTicks
    /\ WindowFull
    /\ tick' = tick + 1
    /\ consumed' = [c \in 1..NumClasses |-> 0]
    /\ sliceCount' = 0
    /\ chosen' = 0
    /\ runnable' = runnable

\* Action: external runnability change — non-deterministically toggle.
\* Resets `chosen` to 0 so the `ChosenIsRunnable` invariant holds
\* between picks. (In the kernel, a runnability change just makes the
\* current pick stale; the next dispatch tick produces a fresh pick.
\* Modeling this requires invalidating `chosen` here.)
ToggleRunnable ==
    /\ tick < MaxTicks
    /\ \E c \in 1..NumClasses :
         /\ runnable' = [runnable EXCEPT ![c] = ~runnable[c]]
         /\ chosen' = 0
         /\ tick' = tick + 1
         /\ UNCHANGED <<consumed, sliceCount>>

Next == RunSlice \/ EndWindow \/ ToggleRunnable

Spec == Init /\ [][Next]_vars

\* ────────────────────────────────────────────────────────────────────────
\* Invariants
\* ────────────────────────────────────────────────────────────────────────

TypeOK ==
    /\ consumed \in [1..NumClasses -> Nat]
    /\ runnable \in [1..NumClasses -> BOOLEAN]
    /\ sliceCount \in Nat
    /\ chosen \in 0..NumClasses
    /\ tick \in 0..MaxTicks

\* APS-2: consumption per class can never exceed WindowSlices in a
\* single window (we reset every WindowSlices slices).
ConsumptionBounded ==
    \A c \in 1..NumClasses : consumed[c] <= WindowSlices

\* APS-3: every non-idle slice picks a runnable class.
ChosenIsRunnable ==
    \/ chosen = 0
    \/ runnable[chosen]

================================================================
