------------------------------ MODULE pi_graph ------------------------------
(*
Priority inheritance on the wait graph (crates/core/sync/src/waitgraph.rs, the
class side in crates/core/sched/src/classes.rs; rfcs/c2-one-dispatch-design.md
2.2 and 4.2, C2-5): tasks block on objects (kernel mutexes, PI futexes) that
other tasks own, the graph computes each task's effective attribute (its base,
or the best of what waits on what it owns, through the chain), and the class
applies it as the attribute the pick ranks. The invariants:

  WaitsAcyclic       P3: a block that would close a cycle is refused and
                     leaves the graph as it was
  NoResidualBoost    P2: a task that no task waits behind runs at its base
  AppliedIsComputed  P5: with no walk in flight, every task's applied
                     attribute is the class's form of its effective one
  DeathWakesOne      P6: an owner's death hands each object it held to its
                     top waiter, waking exactly one
  EdfInheritance     P8: a task boosted by a DL waiter is not out-ranked by a
                     DL task whose deadline is later than that waiter's
  NoOverBoost        P8b: a task boosted by a DL waiter does not out-rank a
                     DL task whose deadline is earlier than that waiter's
  FairInheritance    a fair owner runs at least at the level of a fair
                     waiter behind it (its EEVDF weight is its level's)

The attribute order is Dl (earlier deadline first) > Rt (smaller level first)
> Fair (smaller level first: the heavier EEVDF weight; owner 2026-11-05, the
graph inherits fair weight, which the counted donation did before). `Mapping` is how
the class applies a boost: "inherit" (owner decision D4: a DL-boosted owner
enters DL with the donor's deadline), "today" (classes.rs `pi_prio`: Stop and
Dl become band level 0, below every reservation), "top" (a DL boost placed
above every reservation). P8 is expected to fail for "today" and P8b for
"top"; "inherit" must pass both.

MODEL VS CODE: 4 tasks with fixed base attributes, 2 objects. A walk is one
atomic step per block, release, timeout or death, as under the graph's one
lock (stage 1); the per-object locks of a later stage are not modelled. The
depth cap is above every chain this model can build, so it never stops a
walk (P4 is the host test's: `canary=pi-depth-1`). Death is the robust owner
death of a PI futex or kmutex owner (OWNER_DIED marking). IPC call edges
(stage-2 proxy execution, P7) are not modelled here: ipc_call.tla (C2-8).
NumOps bounds the actions. Mutant selects one injected defect; every
pi_graph_mut_*.cfg must be rejected for the invariant on its `expect:` line.
*)

EXTENDS Integers, FiniteSets

CONSTANTS NumOps, Mapping, Mutant

Mutants == {"none", "cycle-allowed", "unboost-skipped", "walk-stops-early", "death-wakes-all",
            "no-fair-inheritance"}

Tasks   == 1..5
Objects == {1, 2}
NONE    == 0

\* Base attributes: two fair tasks (5 heavier), an RT task, two reservations.
Base == [t \in Tasks |->
           CASE t = 5 -> [k |-> "fair", p |-> 12]
             [] t = 1 -> [k |-> "fair", p |-> 20]
             [] t = 2 -> [k |-> "rt",   p |-> 5]
             [] t = 3 -> [k |-> "dl",   p |-> 2]
             [] t = 4 -> [k |-> "dl",   p |-> 5]]

ASSUME /\ NumOps \in Nat
       /\ Mapping \in {"inherit", "today", "top"}
       /\ Mutant \in Mutants

KindRank(k) == CASE k = "stop" -> 0 [] k = "dl" -> 1 [] k = "rt" -> 2 [] k = "fair" -> 3

\* a ranks strictly above b.
Higher(a, b) == KindRank(a.k) < KindRank(b.k)
                \/ (a.k = b.k /\ a.k \in {"dl", "rt", "fair"} /\ a.p < b.p)

Best(S, dflt) == IF S = {} THEN dflt
                 ELSE CHOOSE a \in S \cup {dflt} : \A b \in S \cup {dflt} : ~Higher(b, a)

VARIABLES
    owner,    \* object -> its owner, NONE when free
    waiting,  \* task -> the object it waits on, NONE
    alive,    \* task -> it has not died
    applied,  \* task -> the attribute the class ranks it by
    wakes,    \* object -> waiters woken by the last death of its owner
    ops

vars == <<owner, waiting, alive, applied, wakes, ops>>

D == Cardinality(Tasks)

\* The graph's functions over an explicit state (own: object -> owner,
\* wt: task -> object waited on), so a walk reads the graph after its step.
OwnedG(t, own)  == {m \in Objects : own[m] = t}
WaitersG(m, wt) == {w \in Tasks : wt[w] = m}
Owned(t)        == OwnedG(t, owner)

\* The effective attribute: the base, or the best of the waiters behind what t
\* owns, through the chain; `d` bounds the recursion (a cycle, under the
\* mutant, must not loop the checker).
RECURSIVE EffG(_, _, _, _)
EffG(t, d, own, wt) ==
    IF d = 0 THEN Base[t]
    ELSE Best({EffG(w, d - 1, own, wt) : w \in UNION {WaitersG(m, wt) : m \in OwnedG(t, own)}}, Base[t])

\* The class's form of t's effective attribute.
ApplyG(t, own, wt) ==
    LET e == EffG(t, D, own, wt) IN
    IF e = Base[t] \/ (Mutant = "no-fair-inheritance" /\ e.k = "fair") THEN Base[t]
    ELSE CASE Mapping = "inherit" -> e
           [] Mapping = "today" -> IF e.k = "dl" THEN [k |-> "rt", p |-> 0] ELSE e
           [] Mapping = "top" -> IF e.k = "dl" THEN [k |-> "stop", p |-> 0] ELSE e

\* The owners up the chain from t: its object's owner, that one's, ...
RECURSIVE UpG(_, _, _, _)
UpG(t, d, own, wt) ==
    IF d = 0 \/ wt[t] = NONE \/ own[wt[t]] = NONE THEN {}
    ELSE {own[wt[t]]} \cup UpG(own[wt[t]], d - 1, own, wt)

\* A walk from `from` re-applies `from` and every owner up its chain on the
\* new graph. The mutant stops after the first task.
Walk(from, own, wt) ==
    LET chain == IF Mutant = "walk-stops-early" THEN from
                 ELSE from \cup UNION {UpG(f, D, own, wt) : f \in from} IN
    [t \in Tasks |-> IF t \in chain THEN ApplyG(t, own, wt) ELSE applied[t]]

Runnable(t) == alive[t] /\ waiting[t] = NONE

\* The best waiter of m (ties: the lowest task id).
Top(m, wt) == CHOOSE w \in WaitersG(m, wt) :
                \A v \in WaitersG(m, wt) : v # w =>
                  (Higher(EffG(w, D, owner, wt), EffG(v, D, owner, wt))
                   \/ (~Higher(EffG(v, D, owner, wt), EffG(w, D, owner, wt)) /\ w < v))

Init == /\ owner = [m \in Objects |-> NONE]
        /\ waiting = [t \in Tasks |-> NONE]
        /\ alive = [t \in Tasks |-> TRUE]
        /\ applied = Base
        /\ wakes = [m \in Objects |-> 0]
        /\ ops = NumOps

\* ---- the graph's operations, each with its walk ----

Acquire(t, m) ==
    /\ Runnable(t) /\ owner[m] = NONE /\ ops > 0 /\ ops' = ops - 1
    /\ owner' = [owner EXCEPT ![m] = t]
    /\ UNCHANGED <<waiting, alive, applied, wakes>>

\* Block on an owned object: refused, and nothing changes, when the owner
\* chain leads back to t (the mutant blocks anyway).
Block(t, m) ==
    /\ Runnable(t) /\ owner[m] \notin {NONE, t} /\ ops > 0 /\ ops' = ops - 1
    /\ LET o == owner[m]
           wt == [waiting EXCEPT ![t] = m] IN
       IF t \in UpG(o, D, owner, waiting) /\ Mutant # "cycle-allowed"
       THEN UNCHANGED <<waiting, applied>>
       ELSE /\ waiting' = wt
            /\ applied' = Walk({o}, owner, wt)
    /\ UNCHANGED <<owner, alive, wakes>>

\* The owner releases m: its top waiter takes it, or it is free. The old
\* owner is re-applied (unboost; skipped by the mutant), the new one too.
Release(t, m) ==
    /\ Runnable(t) /\ owner[m] = t /\ ops > 0 /\ ops' = ops - 1
    /\ IF WaitersG(m, waiting) = {}
       THEN LET own == [owner EXCEPT ![m] = NONE] IN
            /\ owner' = own
            /\ waiting' = waiting
            /\ applied' = IF Mutant = "unboost-skipped" THEN applied
                          ELSE Walk({t}, own, waiting)
       ELSE LET w   == Top(m, waiting)
                own == [owner EXCEPT ![m] = w]
                wt  == [waiting EXCEPT ![w] = NONE] IN
            /\ owner' = own /\ waiting' = wt
            /\ applied' = IF Mutant = "unboost-skipped" THEN Walk({w}, own, wt)
                          ELSE Walk({t, w}, own, wt)
    /\ UNCHANGED <<alive, wakes>>

\* A waiter gives up (timeout, signal): it leaves, and the chain it boosted
\* is re-applied.
Timeout(t) ==
    /\ alive[t] /\ waiting[t] # NONE /\ ops > 0 /\ ops' = ops - 1
    /\ LET o  == owner[waiting[t]]
           wt == [waiting EXCEPT ![t] = NONE] IN
       /\ waiting' = wt
       /\ applied' = Walk({o, t}, owner, wt)
    /\ UNCHANGED <<owner, alive, wakes>>

\* A runnable owner dies: each object it held is marked OWNER_DIED and handed
\* to its top waiter, the one task woken for it (the mutant wakes them all).
Die(t) ==
    /\ Runnable(t) /\ Owned(t) # {} /\ ops > 0 /\ ops' = ops - 1
    /\ LET held == Owned(t)
           newo == [m \in Objects |-> IF m \in held
                                      THEN IF WaitersG(m, waiting) = {} THEN NONE ELSE Top(m, waiting)
                                      ELSE owner[m]]
           woken == {w \in Tasks : waiting[w] \in held /\
                       (Mutant = "death-wakes-all" \/ newo[waiting[w]] = w)}
           wt   == [w \in Tasks |-> IF w \in woken THEN NONE ELSE waiting[w]] IN
       /\ owner' = newo
       /\ waiting' = wt
       /\ wakes' = [m \in Objects |-> IF m \in held
                                      THEN Cardinality({w \in woken : waiting[w] = m})
                                      ELSE wakes[m]]
       /\ applied' = Walk(({newo[m] : m \in held} \ {NONE}) \cup {t}, newo, wt)
    /\ alive' = [alive EXCEPT ![t] = FALSE]


Next == \/ \E t \in Tasks, m \in Objects : Acquire(t, m) \/ Block(t, m) \/ Release(t, m)
        \/ \E t \in Tasks : Timeout(t) \/ Die(t)

Spec == Init /\ [][Next]_vars

\* ---- invariants ----

TypeOK == /\ owner \in [Objects -> Tasks \cup {NONE}]
          /\ waiting \in [Tasks -> Objects \cup {NONE}]
          /\ alive \in [Tasks -> BOOLEAN]
          /\ wakes \in [Objects -> 0..Cardinality(Tasks)]
          /\ ops \in 0..NumOps

WaitsAcyclic == \A t \in Tasks : t \notin UpG(t, D, owner, waiting)

NoResidualBoost ==
    \A t \in Tasks : (\A m \in OwnedG(t, owner) : WaitersG(m, waiting) = {}) => applied[t] = Base[t]

AppliedIsComputed == \A t \in Tasks : applied[t] = ApplyG(t, owner, waiting)

DeathWakesOne == \A m \in Objects : wakes[m] <= 1

\* o is boosted by the DL waiter w: w waits on an object o owns.
BoostedBy(o, w) == waiting[w] # NONE /\ owner[waiting[w]] = o /\ Base[w].k = "dl"

EdfInheritance ==
    \A o, w, r \in Tasks :
        (BoostedBy(o, w) /\ Runnable(o) /\ Runnable(r) /\ r # o
         /\ Base[r].k = "dl" /\ Base[r].p > Base[w].p /\ applied[r] = Base[r])
        => ~Higher(applied[r], applied[o])

NoOverBoost ==
    \A o, w, r \in Tasks :
        (BoostedBy(o, w) /\ Runnable(o) /\ Runnable(r) /\ r # o
         /\ Base[r].k = "dl" /\ Base[r].p < Base[w].p /\ applied[r] = Base[r]
         /\ \A v \in Tasks : BoostedBy(o, v) => Base[v].p >= Base[w].p)
        => ~Higher(applied[o], applied[r])

FairInheritance ==
    \A o, w \in Tasks :
        (waiting[w] # NONE /\ owner[waiting[w]] = o /\ Base[w].k = "fair" /\ Base[o].k = "fair")
        => ~Higher(Base[w], applied[o])

=============================================================================
