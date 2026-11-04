------------------------------- MODULE qsbr -------------------------------
(*
Quiescent-state-based reclamation (crates/core/sync/src/qsbr.rs, qsbr_core.rs,
qsbr_nohz.rs; rfcs/c2-one-dispatch-design.md 4.4, C2-14): one published object,
readers (preempt-off sections on a CPU in the kernel), the per-CPU `eqs` word
(odd = in the kernel, even = user mode on a real-time CPU, or idle) and `qs`
word (the grace-period sequence at the CPU's last return to user mode), a
grace period of the callback task (bump of GP_SEQ, then a snapshot of every
other CPU's `eqs`, then a per-CPU poll), and the callback that frees the
object after it. The invariants:

  NoUseAfterFree    the callback runs only after a grace period that no earlier
                    reader overlaps: when the object is freed no CPU holds a
                    reference taken before it was unpublished
  NoCallbackOnRt    no callback runs on a CPU in the real-time set
  NoIpiToRt         the expedited grace period never sends an IPI to a CPU of
                    the real-time set
  EqsHoldsNoReader  a CPU in an extended quiescent state (even `eqs`, user
                    mode, idle) holds no reader
  ModeMatchesEqs    `eqs` parity and the CPU mode agree: kernel odd; idle even;
                    user mode even on a real-time CPU (its user mode is an EQS,
                    qsbr_nohz.rs), odd on the others (their user mode reports
                    through `qs` at the return to user mode)

MODEL VS CODE: one object, one callback, one grace period of the callback task
(the only caller of the callback path); 3 CPUs, CPU 3 in the real-time set
(RtCpus), the callback task on the lowest CPU outside it (`callback_cpu`).
The task skips its own CPU at the snapshot (`Gp::start` self_cpu) and its steps
need it running, so no reader is open on that CPU. The unpublish and the
enqueue are one step (a reader that begins later does not see the object). The
snapshot is one step; the poll marks each CPU on its own, as `poll_within`
does. `OtherGp` is another waiter bumping GP_SEQ. `Expedite` lets the waiter
kick a CPU it still waits for: the handler reports a quiescent state when no
reader is open there; a real-time CPU is never kicked (it needs none: its user
mode is an EQS). Wrap of the u64 counters, stall detection, offline CPUs,
hotplug, `cpu_stop`, lockdep and several callbacks are not modelled. A grace
period never waits for the CPU it runs on, which is sound only because
synchronize_rcu may sleep and so is never inside a read section. D9 (every CPU
in the real-time set, so the callback task falls back to CPU 0) is the case
NoCallbackOnRt excludes by ASSUME: it is answered by a decision record at boot
(Rule::RcuCallbackCpu), not by this model. NumOps bounds the CPU transitions
that move `eqs` (and OtherGp), which keeps the counters finite. Mutant selects
one injected defect; every qsbr_mut_*.cfg must be rejected for the invariant
named on its `expect:` line.
*)

EXTENDS Integers, FiniteSets

CONSTANTS NumCpus, RtCpus, NumOps, Expedite, Mutant

Mutants == {"none", "skip-cpu-in-kernel", "callback-on-rt-cpu", "ipi-rt",
            "qs-before-read"}

ASSUME /\ NumCpus \in Nat /\ NumCpus > 1
       /\ RtCpus \subseteq 1..NumCpus /\ RtCpus # 1..NumCpus
       /\ NumOps \in Nat /\ NumOps > 0
       /\ Expedite \in BOOLEAN
       /\ Mutant \in Mutants

Cpus   == 1..NumCpus
NonRt  == Cpus \ RtCpus
DONE   == -1

\* callback_cpu(): the lowest CPU outside the set; the mutant picks one inside.
CbCpu == IF Mutant = "callback-on-rt-cpu"
         THEN CHOOSE c \in RtCpus : \A d \in RtCpus : c <= d
         ELSE CHOOSE c \in NonRt : \A d \in NonRt : c <= d

Even(v) == v % 2 = 0

VARIABLES
    eqs,        \* cpu -> counter, odd in the kernel
    qs,         \* cpu -> GP_SEQ at the last return to user mode
    mode,       \* cpu -> "k" kernel, "u" user, "i" idle
    rd,         \* cpu -> a read section is open
    ref,        \* cpu -> the open section holds the object
    published,  \* the object is reachable
    gpseq,      \* GP_SEQ
    seq,        \* the callback task's grace period
    snap,       \* cpu -> the eqs to see change, or DONE
    cb,         \* none, queued, taken, bumped, snapped, done
    ipi,        \* CPUs that received an IPI
    freed,      \* the callback ran
    ranOn,      \* the CPU it ran on, 0 before
    ops

vars == <<eqs, qs, mode, rd, ref, published, gpseq, seq, snap, cb, ipi, freed, ranOn, ops>>

Init == /\ eqs = [c \in Cpus |-> 1]
        /\ qs = [c \in Cpus |-> 0]
        /\ mode = [c \in Cpus |-> "k"]
        /\ rd = [c \in Cpus |-> FALSE]
        /\ ref = [c \in Cpus |-> FALSE]
        /\ published = TRUE
        /\ gpseq = 0
        /\ seq = 0
        /\ snap = [c \in Cpus |-> DONE]
        /\ cb = "none"
        /\ ipi = {}
        /\ freed = FALSE
        /\ ranOn = 0
        /\ ops = NumOps

\* ---- readers: preempt-off sections on a CPU in the kernel ----

ReaderBegin(c) ==
    /\ mode[c] = "k" /\ ~rd[c]
    /\ rd' = [rd EXCEPT ![c] = TRUE]
    /\ ref' = [ref EXCEPT ![c] = published]
    /\ UNCHANGED <<eqs, qs, mode, published, gpseq, seq, snap, cb, ipi, freed, ranOn, ops>>

ReaderEnd(c) ==
    /\ rd[c]
    /\ rd' = [rd EXCEPT ![c] = FALSE]
    /\ ref' = [ref EXCEPT ![c] = FALSE]
    /\ UNCHANGED <<eqs, qs, mode, published, gpseq, seq, snap, cb, ipi, freed, ranOn, ops>>

\* ---- CPU transitions (qsbr.rs TrapBoundary, idle_enter/exit, switch) ----

\* Return to user mode: a real-time CPU enters its EQS; the others report in `qs`.
\* The mutant lets the CPU report with a read section still open.
ToUser(c) ==
    /\ mode[c] = "k" /\ (~rd[c] \/ Mutant = "qs-before-read")
    /\ mode' = [mode EXCEPT ![c] = "u"]
    /\ IF c \in RtCpus
       THEN /\ ops > 0 /\ ops' = ops - 1
            /\ eqs' = [eqs EXCEPT ![c] = @ + 1]
            /\ qs' = qs
       ELSE /\ qs' = [qs EXCEPT ![c] = gpseq]
            /\ UNCHANGED <<eqs, ops>>
    /\ UNCHANGED <<rd, ref, published, gpseq, seq, snap, cb, ipi, freed, ranOn>>

FromUser(c) ==
    /\ mode[c] = "u"
    /\ mode' = [mode EXCEPT ![c] = "k"]
    /\ IF c \in RtCpus
       THEN /\ ops > 0 /\ ops' = ops - 1
            /\ eqs' = [eqs EXCEPT ![c] = @ + 1]
       ELSE UNCHANGED <<eqs, ops>>
    /\ UNCHANGED <<qs, rd, ref, published, gpseq, seq, snap, cb, ipi, freed, ranOn>>

IdleEnter(c) ==
    /\ mode[c] = "k" /\ (~rd[c] \/ Mutant = "qs-before-read")
    /\ ops > 0 /\ ops' = ops - 1
    /\ mode' = [mode EXCEPT ![c] = "i"]
    /\ eqs' = [eqs EXCEPT ![c] = @ + 1]
    /\ UNCHANGED <<qs, rd, ref, published, gpseq, seq, snap, cb, ipi, freed, ranOn>>

IdleExit(c) ==
    /\ mode[c] = "i"
    /\ ops > 0 /\ ops' = ops - 1
    /\ mode' = [mode EXCEPT ![c] = "k"]
    /\ eqs' = [eqs EXCEPT ![c] = @ + 1]
    /\ UNCHANGED <<qs, rd, ref, published, gpseq, seq, snap, cb, ipi, freed, ranOn>>

\* A context switch needs preemption on, so no read section is open.
Switch(c) ==
    /\ mode[c] = "k" /\ ~rd[c]
    /\ ops > 0 /\ ops' = ops - 1
    /\ eqs' = [eqs EXCEPT ![c] = @ + 2]
    /\ UNCHANGED <<qs, mode, rd, ref, published, gpseq, seq, snap, cb, ipi, freed, ranOn>>

\* Another waiter starts a grace period.
OtherGp ==
    /\ ops > 0 /\ ops' = ops - 1
    /\ gpseq' = gpseq + 1
    /\ UNCHANGED <<eqs, qs, mode, rd, ref, published, seq, snap, cb, ipi, freed, ranOn>>

\* ---- the updater and the callback task ----

\* Unpublish, then call_rcu: the callback is queued.
Unpublish ==
    /\ cb = "none" /\ published
    /\ published' = FALSE
    /\ cb' = "queued"
    /\ UNCHANGED <<eqs, qs, mode, rd, ref, gpseq, seq, snap, ipi, freed, ranOn, ops>>

\* The task's steps run on its CPU, in the kernel with no reader open there.
TaskRuns == mode[CbCpu] = "k" /\ ~rd[CbCpu]

TaskTake ==
    /\ cb = "queued" /\ TaskRuns
    /\ cb' = "taken"
    /\ UNCHANGED <<eqs, qs, mode, rd, ref, published, gpseq, seq, snap, ipi, freed, ranOn, ops>>

TaskBump ==
    /\ cb = "taken" /\ TaskRuns
    /\ gpseq' = gpseq + 1 /\ seq' = gpseq + 1
    /\ cb' = "bumped"
    /\ UNCHANGED <<eqs, qs, mode, rd, ref, published, snap, ipi, freed, ranOn, ops>>

Snapshot(c) ==
    IF c = CbCpu THEN DONE
    ELSE IF Even(eqs[c]) \/ Mutant = "skip-cpu-in-kernel" THEN DONE
    ELSE eqs[c]

TaskSnap ==
    /\ cb = "bumped" /\ TaskRuns
    /\ snap' = [c \in Cpus |-> Snapshot(c)]
    /\ cb' = "snapped"
    /\ UNCHANGED <<eqs, qs, mode, rd, ref, published, gpseq, seq, ipi, freed, ranOn, ops>>

TaskPoll(c) ==
    /\ cb = "snapped" /\ TaskRuns
    /\ snap[c] # DONE
    /\ eqs[c] # snap[c] \/ qs[c] >= seq
    /\ snap' = [snap EXCEPT ![c] = DONE]
    /\ UNCHANGED <<eqs, qs, mode, rd, ref, published, gpseq, seq, cb, ipi, freed, ranOn, ops>>

\* Expedited: the waiter kicks a CPU it still waits for; the handler reports a
\* quiescent state if no reader is open there. A real-time CPU is not kicked.
Kick(c) ==
    /\ Expedite /\ cb = "snapped" /\ snap[c] # DONE
    /\ c \notin ipi
    /\ c \notin RtCpus \/ Mutant = "ipi-rt"
    /\ mode[c] \in {"k", "u"}
    /\ ipi' = ipi \cup {c}
    /\ qs' = IF rd[c] THEN qs ELSE [qs EXCEPT ![c] = gpseq]
    /\ UNCHANGED <<eqs, mode, rd, ref, published, gpseq, seq, snap, cb, freed, ranOn, ops>>

TaskInvoke ==
    /\ cb = "snapped" /\ TaskRuns
    /\ \A c \in Cpus : snap[c] = DONE
    /\ cb' = "done" /\ freed' = TRUE /\ ranOn' = CbCpu
    /\ UNCHANGED <<eqs, qs, mode, rd, ref, published, gpseq, seq, snap, ipi, ops>>

Next == \/ \E c \in Cpus : ReaderBegin(c) \/ ReaderEnd(c) \/ ToUser(c) \/ FromUser(c)
                           \/ IdleEnter(c) \/ IdleExit(c) \/ Switch(c)
                           \/ TaskPoll(c) \/ Kick(c)
        \/ OtherGp \/ Unpublish \/ TaskTake \/ TaskBump \/ TaskSnap \/ TaskInvoke

Spec == Init /\ [][Next]_vars

\* ---- invariants ----

TypeOK == /\ eqs \in [Cpus -> Nat] /\ qs \in [Cpus -> Nat]
          /\ mode \in [Cpus -> {"k", "u", "i"}]
          /\ rd \in [Cpus -> BOOLEAN] /\ ref \in [Cpus -> BOOLEAN]
          /\ \A c \in Cpus : ref[c] => rd[c]
          /\ published \in BOOLEAN /\ gpseq \in Nat /\ seq \in Nat
          /\ snap \in [Cpus -> Int]
          /\ cb \in {"none", "queued", "taken", "bumped", "snapped", "done"}
          /\ ipi \subseteq Cpus /\ freed \in BOOLEAN /\ ranOn \in 0..NumCpus
          /\ ops \in 0..NumOps

NoUseAfterFree == freed => \A c \in Cpus : ~ref[c]

NoCallbackOnRt == freed => ranOn \notin RtCpus

NoIpiToRt == ipi \cap RtCpus = {}

EqsHoldsNoReader == \A c \in Cpus : (Even(eqs[c]) \/ mode[c] # "k") => ~rd[c]

ModeMatchesEqs ==
    \A c \in Cpus :
        /\ mode[c] = "k" => ~Even(eqs[c])
        /\ mode[c] = "i" => Even(eqs[c])
        /\ mode[c] = "u" => (Even(eqs[c]) <=> c \in RtCpus)

=============================================================================
