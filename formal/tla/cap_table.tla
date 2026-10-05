--------------------------- MODULE cap_table ---------------------------
(*
AZOS — Per-task capability table

Models the abstract behaviour of `crates/core/ipc/src/cap.rs::CapTable`. The
spec is intentionally cap-shape-agnostic: it tracks slot occupancy,
generation, and outstanding handles. The point is to verify the
invariants of RFC-0003 §"Forgery resistance":

  INV-1  Generation values per slot are monotonic; a slot that reaches
         MaxGen is RETIRED, not wrapped — no future grant ever reuses it.
  INV-2  A handle is "valid" iff the slot's current generation matches
         the handle's generation **and** the slot is occupied.
  INV-3  Once revoked, a handle never becomes valid again without an
         explicit grant on the same slot incrementing the generation.
  INV-4  A retired slot is never granted again (`RetiredNeverReissued`).

Run with TLC, default config in `cap_table.cfg` (next to this file).

MODEL VS CODE (doc audit, 2026-09-26, updated to match A2's retirement
scheme): this spec now models the same policy `crates/core/ipc/src/cap.rs`
does — a slot's generation is monotonic and RETIRES at `MaxGen` (the
model's stand-in for `CapHandle::MAX_GENERATION`, 8,191 in the real
13-bit field) rather than wrapping back to 1. `Grant` below refuses a
retired slot the same way `CapTable::grant_raw` does (`cap.rs:333-345,
831-833`). This model is still per-slot only: a separate, pool-wide
24-bit generation (one per object kind — `crates/core/ipc/src/shm.rs:170`,
`crates/core/ipc/src/objref.rs:146-154`) DOES wrap, and its wrap revokes
every capability of that kind across every task's table at once. That
pool-wide behaviour has no counterpart here and would need a second
model. No TLC run against this file is recorded past 2026-05-14 (any
older recorded result describes the OLD, wrapping version of this spec);
check the gate row in `tools/ci_check.sh` before trusting any run date.
*)

EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS NumSlots,    \* total slots, e.g. 4 for fast model-check
          MaxGen,      \* maximum representable generation, e.g. 3
          NumOps       \* bound on operations to explore, e.g. 8

ASSUME /\ NumSlots \in Nat /\ NumSlots > 0
       /\ MaxGen \in Nat /\ MaxGen > 0
       /\ NumOps \in Nat /\ NumOps > 0

VARIABLES
    slots,             \* function: slot -> [occupied: BOOL, gen: Nat, retired: BOOL]
    handles,           \* set of records {slot, gen} ever issued
    revoked,           \* set of records {slot, gen} that have been revoked
    opCount            \* operation counter, for bounding

vars == <<slots, handles, revoked, opCount>>

\* Initial state: every slot empty, generation 0, not retired, no handles.
Init ==
    /\ slots = [s \in 1..NumSlots |-> [occupied |-> FALSE, gen |-> 0, retired |-> FALSE]]
    /\ handles = {}
    /\ revoked = {}
    /\ opCount = 0

\* "Pick a free, non-retired slot" — any unoccupied, ungrantable-no-more
\* slot is excluded, mirroring `grant_raw` skipping a retired slot.
PickFree ==
    CHOOSE s \in 1..NumSlots : ~slots[s].occupied /\ ~slots[s].retired

CanGrant == \E s \in 1..NumSlots : ~slots[s].occupied /\ ~slots[s].retired

\* Action: grant a fresh cap on a free, non-retired slot, bumping the
\* generation. At MaxGen the slot RETIRES instead of granting past it —
\* `bump_generation` returning `None` in the real code.
Grant ==
    /\ opCount < NumOps
    /\ CanGrant
    /\ LET s == PickFree
           prev == slots[s].gen
       IN IF prev >= MaxGen
          THEN /\ slots' = [slots EXCEPT ![s] = [occupied |-> FALSE, gen |-> prev, retired |-> TRUE]]
               /\ handles' = handles
               /\ revoked' = revoked
               /\ opCount' = opCount + 1
          ELSE LET next == prev + 1
               IN /\ slots' = [slots EXCEPT ![s] = [occupied |-> TRUE, gen |-> next, retired |-> FALSE]]
                  /\ handles' = handles \cup {[slot |-> s, gen |-> next]}
                  /\ revoked' = revoked
                  /\ opCount' = opCount + 1

\* Action: revoke any currently-occupied slot. `retired` is carried
\* through unchanged — revoking does not un-retire a slot, and a slot
\* that was never retired stays not-retired.
Revoke ==
    /\ opCount < NumOps
    /\ \E s \in 1..NumSlots : slots[s].occupied
    /\ \E s \in 1..NumSlots :
         /\ slots[s].occupied
         /\ slots' = [slots EXCEPT ![s] = [occupied |-> FALSE, gen |-> slots[s].gen, retired |-> slots[s].retired]]
         /\ revoked' = revoked \cup {[slot |-> s, gen |-> slots[s].gen]}
         /\ handles' = handles
         /\ opCount' = opCount + 1

Next == Grant \/ Revoke

Spec == Init /\ [][Next]_vars

\* ───────────────────────────────────────────────────────────────────────
\* Invariants
\* ───────────────────────────────────────────────────────────────────────

\* INV-A: A handle is "valid" iff its generation matches the slot's
\* current generation AND the slot is occupied AND it has not been
\* explicitly revoked at this generation.
ValidHandle(h) ==
    /\ slots[h.slot].occupied
    /\ slots[h.slot].gen = h.gen
    /\ h \notin revoked

\* INV-B: At most one valid handle per slot (since granting bumps the gen
\* and we don't dup in this model).
AtMostOneValidPerSlot ==
    \A s \in 1..NumSlots :
        Cardinality({h \in handles : h.slot = s /\ ValidHandle(h)}) <= 1

\* INV-C: A revoked handle is never valid.
RevokedNeverValid == \A h \in revoked : ~ValidHandle(h)

\* INV-D: Generations are bounded by MaxGen.
GenInRange == \A s \in 1..NumSlots : slots[s].gen <= MaxGen

\* INV-E: a retired slot is never granted again — once `retired`, always
\* `retired` and never `occupied` by a fresh grant afterwards. This is the
\* invariant A2's fix depends on: the whole point of retiring instead of
\* wrapping is that no future holder can collide with a generation a past
\* holder still has.
RetiredNeverReissued ==
    \A s \in 1..NumSlots :
        slots[s].retired => slots[s].gen = MaxGen /\ ~slots[s].occupied

TypeOK ==
    /\ slots \in [1..NumSlots -> [occupied: BOOLEAN, gen: 0..MaxGen, retired: BOOLEAN]]
    /\ handles \subseteq [slot: 1..NumSlots, gen: 1..MaxGen]
    /\ revoked \subseteq [slot: 1..NumSlots, gen: 1..MaxGen]
    /\ opCount \in 0..NumOps

\* ───────────────────────────────────────────────────────────────────────
\* The properties we want TLC to check
\* ───────────────────────────────────────────────────────────────────────

\* These are passed as INVARIANT in the .cfg file:
\*   - TypeOK
\*   - AtMostOneValidPerSlot
\*   - RevokedNeverValid
\*   - GenInRange
\*   - RetiredNeverReissued

================================================================
