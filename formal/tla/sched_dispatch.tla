--------------------------- MODULE sched_dispatch ---------------------------
(*
One dispatch over the class table (crates/core/sched/src/sc.rs, classes.rs,
scheduler/mod.rs do_schedule; rfcs/c2-one-dispatch-design.md 2.1 and 4.1,
C2-1): per-CPU queues per class, the walk Dl > Rt > Fair (the first class with
an eligible task wins, the running task competing), the class's own throttle
(`force`), a remote enqueue with its doorbell, a class change, the tick, and
the IPC direct switch. The invariants:

  WalkPicksBest        I-D1: the walk's pick is the best eligible task of the
                       best class on that CPU, the running task included
                       unless its class throttles it
  OneQueue             I-D2: a task is in at most one queue of one CPU, its
                       `queued` flag says so, a queued task is Ready, a
                       current task is in no queue, and no Ready task is lost
                       (queued, or picked and about to run)
  QueueMatchesClass    I-D3: a queued task sits in its class's queue
  DirectSwitchRefines  I-D4: a direct switch runs the task the walk would
                       have picked after enqueueing it
  TickForces           I-D5: the tick asks the running task to yield exactly
                       when its class throttles it or a better task is queued
  NoLostResched        I-D6: a queued task that beats the running one is
                       always announced (need_resched or the doorbell)

MODEL VS CODE: 2 CPUs, 3 tasks, the classes that order real work (Stop is
the exempt-loop slot and Idle is "nothing to run", cur = 0). Inside a class
the order is a fixed key per task (the band level, the EDF deadline, the
EEVDF virtual deadline): the arithmetic is host-tested (eevdf_core.rs,
rt_core.rs), not modelled. `thr` is the class throttle: a reservation past its
budget, a band past its cap (the RT band's cap is per CPU in the code, per task
here). Fair is never throttled. The walk runs under the CPU lock in one step;
the lock is dropped between the pick and the switch (`pc` = "picked"), which
is the window a remote enqueue may hit. `Bucket` is today's ready-bitmap
bucket of a fair task, which the direct-switch rule of today reads
(DirectRule = "bucket", ipc_direct::allowed); the class walk's query is
DirectRule = "walk" (`would_pick`). A task woken while still current on its
CPU (blocked, not yet switched out) is not modelled: the code's wake waits for
the switch-out (`on_cpu`). NumOps bounds the actions that change the workload.
Mutant selects one injected defect; every sched_dispatch_mut_*.cfg must be
rejected for the invariant named on its `expect:` line.
*)

EXTENDS Integers, FiniteSets

CONSTANTS NumCpus, NumOps, DirectRule, Mutant

\* Three tasks: a reservation and two fair tasks; task 3 has the earliest key
\* (virtual deadline) but the worse ready-bitmap bucket.
NumTasks  == 3
Key       == <<3, 2, 1>>
Bucket    == <<0, 5, 9>>
InitClass == <<"dl", "fair", "fair">>

Mutants == {"none", "pick-skips-dl", "class-change-without-requeue",
            "direct-switch-no-check", "tick-ignores-force", "enqueue-after-pick-race"}

Cpus    == 1..NumCpus
Tasks   == 1..NumTasks
Classes == {"dl", "rt", "fair"}
Rank(k) == CASE k = "dl" -> 1 [] k = "rt" -> 2 [] k = "fair" -> 3

ASSUME /\ NumCpus \in Nat /\ NumCpus > 0
       /\ \A a, b \in Tasks : a # b => Key[a] # Key[b]
       /\ NumOps \in Nat /\ DirectRule \in {"walk", "bucket"}
       /\ Mutant \in Mutants

VARIABLES
    class,    \* task -> its class (the SC's)
    st,       \* task -> "ready", "run", "blocked"
    inq,      \* <<cpu, class>> -> the tasks queued there
    queued,   \* task -> the K-C12 flag
    thr,      \* task -> its class throttles it
    cur,      \* cpu -> the current task, 0 = idle
    nr,       \* cpu -> need_resched
    bell,     \* cpu -> a doorbell is pending
    pc,       \* cpu -> "run", or "picked" (lock dropped, switch to come)
    nxt,      \* cpu -> what the pick chose (cur = keep, 0 = idle)
    bad,      \* the invariants recorded at the step that decides
    ops

vars == <<class, st, inq, queued, thr, cur, nr, bell, pc, nxt, bad, ops>>

Better(a, b) == Rank(class[a]) < Rank(class[b])
                \/ (class[a] = class[b] /\ Key[a] < Key[b])

Best(S) == CHOOSE t \in S : \A u \in S \ {t} : Better(t, u)

Forced(t)   == class[t] \in {"dl", "rt"} /\ thr[t]
Eligible(t) == ~Forced(t)

Queued(c)   == UNION {inq[<<c, k>>] : k \in Classes}
Q(c)        == {t \in Queued(c) : Eligible(t)}
Runs(c)     == cur[c] # 0 /\ st[cur[c]] = "run"
CurGone(c)  == cur[c] # 0 /\ st[cur[c]] = "blocked"
IsCur(t)    == \E c \in Cpus : cur[c] = t

\* The candidates of a pick on c: the queued eligible tasks and the running
\* task unless throttled. `drop` is the mutant's class the walk skips.
Cands(c, drop) ==
    {t \in Q(c) : class[t] # drop}
    \cup (IF Runs(c) /\ Eligible(cur[c]) THEN {cur[c]} ELSE {})

PickOf(c, drop) ==
    LET S == Cands(c, drop) IN
    IF S # {} THEN Best(S) ELSE IF Runs(c) THEN cur[c] ELSE 0

\* A queued task that the running one must give way to.
Beats(t, c) == cur[c] = 0 \/ (Runs(c) /\ Eligible(cur[c]) /\ Better(t, cur[c]))

Init == /\ class = InitClass
        /\ st = [t \in Tasks |-> "blocked"]
        /\ inq = [x \in Cpus \X Classes |-> {}]
        /\ queued = [t \in Tasks |-> FALSE]
        /\ thr = [t \in Tasks |-> FALSE]
        /\ cur = [c \in Cpus |-> 0]
        /\ nr = [c \in Cpus |-> FALSE]
        /\ bell = [c \in Cpus |-> FALSE]
        /\ pc = [c \in Cpus |-> "run"]
        /\ nxt = [c \in Cpus |-> 0]
        /\ bad = [i \in {"pick", "tick", "direct"} |-> FALSE]
        /\ ops = NumOps

Enq(q, c, t) == [q EXCEPT ![<<c, class[t]>>] = @ \cup {t}]

\* ---- the switch path ----

Schedule(c) ==
    /\ pc[c] = "run" /\ (nr[c] \/ bell[c] \/ CurGone(c))
    /\ LET p == PickOf(c, IF Mutant = "pick-skips-dl" THEN "dl" ELSE "none") IN
       /\ nxt' = [nxt EXCEPT ![c] = p]
       /\ bad' = [bad EXCEPT !["pick"] = @ \/ p # PickOf(c, "none")]
       /\ IF p # 0 /\ p # cur[c]
          THEN /\ inq' = [inq EXCEPT ![<<c, class[p]>>] = @ \ {p}]
               /\ queued' = [queued EXCEPT ![p] = FALSE]
          ELSE UNCHANGED <<inq, queued>>
    /\ nr' = [nr EXCEPT ![c] = FALSE] /\ bell' = [bell EXCEPT ![c] = FALSE]
    /\ pc' = [pc EXCEPT ![c] = "picked"]
    /\ UNCHANGED <<class, st, thr, cur, ops>>

\* The outgoing task goes back to its queue if it still runs (K-C26).
Switch(c) ==
    /\ pc[c] = "picked"
    /\ LET old == cur[c]
           new == nxt[c] IN
       IF new = old
       THEN UNCHANGED <<st, inq, queued, cur>>
       ELSE /\ cur' = [cur EXCEPT ![c] = new]
            /\ LET back == old # 0 /\ st[old] = "run" IN
               /\ inq' = IF back THEN Enq(inq, c, old) ELSE inq
               /\ queued' = IF back THEN [queued EXCEPT ![old] = TRUE] ELSE queued
               /\ st' = [t \in Tasks |-> IF t = new THEN "run"
                                         ELSE IF back /\ t = old THEN "ready"
                                         ELSE st[t]]
    /\ pc' = [pc EXCEPT ![c] = "run"]
    /\ UNCHANGED <<class, thr, nr, bell, nxt, bad, ops>>

\* ---- the workload ----

Block(c) ==
    /\ pc[c] = "run" /\ Runs(c) /\ ops > 0 /\ ops' = ops - 1
    /\ st' = [st EXCEPT ![cur[c]] = "blocked"]
    /\ UNCHANGED <<class, inq, queued, thr, cur, nr, bell, pc, nxt, bad>>

\* A wake onto c. From c itself (the waker is c's running task) it sets
\* need_resched when t beats the waker (wake/preempt.rs); from another CPU it
\* always rings c's doorbell (ring_doorbell: every remote enqueue that grew
\* the queue). The mutant skips the doorbell when c is past its pick, taking
\* it for a CPU about to choose.
Wake(t, c) ==
    /\ st[t] = "blocked" /\ ~IsCur(t) /\ ops > 0 /\ ops' = ops - 1
    /\ st' = [st EXCEPT ![t] = "ready"]
    /\ inq' = Enq(inq, c, t)
    /\ queued' = [queued EXCEPT ![t] = TRUE]
    /\ \/ /\ pc[c] = "run" /\ Runs(c)
          /\ nr' = [nr EXCEPT ![c] = @ \/ (Eligible(t) /\ Beats(t, c))]
          /\ bell' = bell
       \/ /\ nr' = nr
          /\ bell' = IF Mutant = "enqueue-after-pick-race" /\ pc[c] = "picked" THEN bell
                     ELSE [bell EXCEPT ![c] = TRUE]
    /\ UNCHANGED <<class, thr, cur, pc, nxt, bad>>

\* A class change (boost, admission, release) is dequeue, change, enqueue under
\* the CPU lock; the mutant changes the class in place.
ChangeClass(t, k) ==
    /\ class[t] # k /\ ops > 0 /\ ops' = ops - 1
    /\ class' = [class EXCEPT ![t] = k]
    /\ \/ /\ queued[t]
          /\ \E c \in Cpus :
               /\ t \in Queued(c)
               /\ inq' = IF Mutant = "class-change-without-requeue" THEN inq
                         ELSE [inq EXCEPT ![<<c, class[t]>>] = @ \ {t},
                                          ![<<c, k>>] = @ \cup {t}]
               /\ nr' = [nr EXCEPT ![c] = TRUE]
       \* Not queued: the CPU that runs it, or has picked it and is about to,
       \* is told (its queue may now hold a better task).
       \/ /\ ~queued[t]
          /\ inq' = inq
          /\ nr' = [c \in Cpus |-> nr[c] \/ cur[c] = t \/ (pc[c] = "picked" /\ nxt[c] = t)]
    /\ UNCHANGED <<st, queued, thr, cur, bell, pc, nxt, bad>>

\* The tick charges the running task (its class may throttle it now) and asks
\* it to yield when it is throttled or a better task is queued.
Tick(c) ==
    /\ pc[c] = "run" /\ Runs(c) /\ ops > 0 /\ ops' = ops - 1
    /\ \E spent \in BOOLEAN :
         LET t    == cur[c]
             thr2 == [thr EXCEPT ![t] = @ \/ (spent /\ class[t] \in {"dl", "rt"})]
             f    == class[t] \in {"dl", "rt"} /\ thr2[t]
             better == \E u \in Queued(c) :
                         ~(class[u] \in {"dl", "rt"} /\ thr2[u]) /\ (f \/ Better(u, t))
             spec == f \/ better
             impl == IF Mutant = "tick-ignores-force" THEN better /\ ~f ELSE spec
         IN /\ thr' = thr2
            /\ nr' = [nr EXCEPT ![c] = @ \/ impl]
            /\ bad' = [bad EXCEPT !["tick"] = @ \/ impl # spec]
    /\ UNCHANGED <<class, st, inq, queued, cur, bell, pc, nxt>>

\* A throttled reservation is replenished; its CPU is told if it now wins.
Replenish(t) ==
    /\ thr[t] /\ ops > 0 /\ ops' = ops - 1
    /\ thr' = [thr EXCEPT ![t] = FALSE]
    /\ nr' = [c \in Cpus |-> nr[c] \/ (t \in Queued(c)) \/ cur[c] = t]
    /\ UNCHANGED <<class, st, inq, queued, cur, bell, pc, nxt, bad>>

\* The IPC direct switch on c: the running caller blocks and the woken server
\* runs at once, never queued, when the rule allows; else an ordinary wake.
Allowed(c, a, t) ==
    CASE Mutant = "direct-switch-no-check" -> TRUE
      [] DirectRule = "walk" ->
           \A u \in Q(c) : Better(t, u)
      [] DirectRule = "bucket" ->
           \* ipc_direct::allowed: no band or reservation on either side or on
           \* the hart, and nothing queued at the target's bucket or better.
           /\ class[a] = "fair" /\ class[t] = "fair"
           /\ \A u \in Queued(c) : class[u] = "fair" /\ Bucket[u] > Bucket[t]

DirectCall(c, t) ==
    /\ pc[c] = "run" /\ Runs(c) /\ st[t] = "blocked" /\ ~IsCur(t) /\ Eligible(t)
    /\ ops > 0 /\ ops' = ops - 1
    /\ LET a == cur[c] IN
       IF Allowed(c, a, t)
       THEN /\ cur' = [cur EXCEPT ![c] = t]
            /\ st' = [st EXCEPT ![a] = "blocked", ![t] = "run"]
            /\ bad' = [bad EXCEPT !["direct"] = @ \/ ~(\A u \in Q(c) : Better(t, u))]
            /\ UNCHANGED <<inq, queued, nr>>
       ELSE /\ st' = [st EXCEPT ![a] = "blocked", ![t] = "ready"]
            /\ inq' = Enq(inq, c, t)
            /\ queued' = [queued EXCEPT ![t] = TRUE]
            /\ nr' = [nr EXCEPT ![c] = TRUE]
            /\ UNCHANGED <<cur, bad>>
    /\ UNCHANGED <<class, thr, bell, pc, nxt>>

Next == \/ \E c \in Cpus : Schedule(c) \/ Switch(c) \/ Block(c) \/ Tick(c)
        \/ \E c \in Cpus, t \in Tasks : Wake(t, c) \/ DirectCall(c, t)
        \/ \E t \in Tasks, k \in Classes : ChangeClass(t, k)
        \/ \E t \in Tasks : Replenish(t)

Spec == Init /\ [][Next]_vars

\* ---- invariants ----

TypeOK == /\ class \in [Tasks -> Classes]
          /\ st \in [Tasks -> {"ready", "run", "blocked"}]
          /\ inq \in [Cpus \X Classes -> SUBSET Tasks]
          /\ queued \in [Tasks -> BOOLEAN] /\ thr \in [Tasks -> BOOLEAN]
          /\ cur \in [Cpus -> 0..NumTasks]
          /\ nr \in [Cpus -> BOOLEAN] /\ bell \in [Cpus -> BOOLEAN]
          /\ pc \in [Cpus -> {"run", "picked"}] /\ nxt \in [Cpus -> 0..NumTasks]
          /\ ops \in 0..NumOps

WalkPicksBest == ~bad["pick"]

Picked(t) == \E c \in Cpus : pc[c] = "picked" /\ nxt[c] = t /\ cur[c] # t

OneQueue ==
    \A t \in Tasks :
        /\ Cardinality({x \in Cpus \X Classes : t \in inq[x]}) <= 1
        /\ queued[t] <=> \E x \in Cpus \X Classes : t \in inq[x]
        /\ queued[t] => st[t] = "ready"
        /\ IsCur(t) => ~queued[t]
        /\ Cardinality({c \in Cpus : cur[c] = t}) <= 1
        /\ st[t] = "ready" => (queued[t] \/ Picked(t))
        /\ st[t] = "run" => IsCur(t)

QueueMatchesClass == \A x \in Cpus \X Classes : \A t \in inq[x] : class[t] = x[2]

DirectSwitchRefines == ~bad["direct"]

TickForces == ~bad["tick"]

NoLostResched ==
    \A c \in Cpus :
        (pc[c] = "run" /\ ~CurGone(c) /\ \E t \in Q(c) : Beats(t, c)) => (nr[c] \/ bell[c])

=============================================================================
