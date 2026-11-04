------------------------------- MODULE mm -------------------------------
(*
User-page memory model: one slot word per object page (the truth), a PTE as a
cache of it, flat copy-on-write by frame refcount, deferred frame release
behind a shootdown, and the lock order. Invariant names map to the numbered
list in the memory-model design (rfcs/c1-mm-one-model-design.md, 2.9):

  PteIsCache, TlbWritableImpliesSole 1   RefIsHolders 2   NoFreeWhileNamed 3
  NoInstallAfterRelease 4   ZeroOnFirstUse 5   MapperIsReverse 6
  ChargeAtReserve 7   FrameAccounted, DestroyLeavesNothing 8
  LockedNeverReclaimed 13
  LockOrder, SupplyUnlocked, ShootdownAfterRelease, FaultNeverTakesMm: 2.10
  TlbNamesSlotOrPending: a stale TLB entry names a frame only while a
  released reference to it is pending, which is what makes 3 enforceable.

MODEL VS CODE: one page per object; AS 1 owns private object 1, AS 2 owns
private object 2 (the fork clone), object 3 is shared and never cloned.
Compressed and Swapped are one state. Resv, huge runs, Phys and Contig kinds,
page-table shape, A/D bits, NUMA, colours and caps are not modelled, nor are
the kernel-memory invariants (9-12) and liveness. Unmap and fork complete
their shootdown before they return. Mutant selects one injected defect; every
mm_mut_*.cfg must be rejected for the invariant named on its `expect:` line.
*)

EXTENDS Integers, FiniteSets, Sequences

CONSTANTS NumFrames, NumHarts, NumOps, Mutant

Mutants == {"none", "cow-skip", "fork-no-flush", "free-early", "uaccess-skip",
            "store-early", "install-no-refind", "no-zero", "map-no-mapper",
            "charge-on-fault", "drop-leak", "drop-twice",
            "destroy-skip-mapping", "reclaim-locked", "reclaim-inversion",
            "supply-locked", "shootdown-locked", "fault-takes-mm",
            "unmap-no-flush", "cow-no-pend"}

ASSUME /\ NumFrames \in Nat /\ NumFrames > 0
       /\ NumHarts \in Nat /\ NumHarts > 0
       /\ NumOps \in Nat /\ NumOps > 0
       /\ Mutant \in Mutants

ASes    == 1..2
Objs    == 1..3
Private == {1, 2}
Frames  == 1..NumFrames
Harts   == 1..NumHarts
Cells   == {<<1, 1>>, <<1, 3>>, <<2, 2>>, <<2, 3>>}
AsOf(c)  == c[1]
ObjOf(c) == c[2]

LockNames == {"mm", "AS", "Obj"}
Rank == [mm |-> 1, AS |-> 2, Obj |-> 3]

VARIABLES
    slot,     \* obj -> [st, f]: the page state, the only truth
    alive,    \* obj -> private object exists
    maps,     \* cell -> 0 none, 1 read-only, 2 read-write mapping
    mgen,     \* cell -> mapping epoch, bumped on unmap
    mappers,  \* obj -> set of AS: the reverse map
    locked,   \* obj -> has a locked mapper
    sdata,    \* obj -> content stored while Swapped
    pte,      \* cell -> page-table entry (cache)
    tlb,      \* hart -> cell -> cached entry
    uacc,     \* hart -> open user-copy section [f, c]
    rc,       \* frame -> holders - 1, including released-but-unsettled refs
    pend,     \* frame -> references released, decrement deferred to Settle
    free,     \* set of free frames
    content,  \* frame -> 0 zero, 1 written, 2 stale from a previous holder
    ft,       \* hart -> fault in flight
    charge,   \* domain charge, in pages
    asLive,   \* AS -> exists
    ops,      \* bound on Map and Fork
    acq       \* lock chain taken by the last action

objV  == <<slot, alive, mappers, locked, sdata>>
mapV  == <<maps, mgen>>
hwV   == <<pte, tlb, uacc>>
frV   == <<rc, pend, free, content>>
miscV == <<ft, charge, asLive, ops, acq>>
vars  == <<objV, mapV, hwV, frV, miscV>>

ES    == [st |-> "Empty", f |-> 0]
NoPte == [present |-> FALSE, writable |-> FALSE, f |-> 0]
NoUa  == [f |-> 0, c |-> <<1, 1>>]
NoFault == [st |-> "idle", k |-> "none", c |-> <<1, 1>>, w |-> FALSE,
            g |-> 0, fr |-> 0, of |-> 0]

SlotNames(o, f) == slot[o].st \in {"Frame", "InTransit"} /\ slot[o].f = f
N(f) == Cardinality({o \in Objs : SlotNames(o, f)})
TlbNames(f)  == \E h \in Harts, c \in Cells : tlb[h][c].f = f
UaccNames(f) == \E h \in Harts : uacc[h].f = f
StaleTlb(f)  == \E h \in Harts, c \in Cells :
                    tlb[h][c].f = f /\ ~SlotNames(ObjOf(c), f)
StalePte(f)  == \E c \in Cells : pte[c].f = f /\ ~SlotNames(ObjOf(c), f)
StaleUacc(f) == \E h \in Harts :
                    uacc[h].f = f /\ ~SlotNames(ObjOf(uacc[h].c), f)
Flushable(f) == StaleTlb(f) \/ (\E o \in Objs : slot[o].st = "InTransit" /\ slot[o].f = f)
StaleOut(f) == [content EXCEPT ![f] = IF @ = 1 THEN 2 ELSE @]
DropN == IF Mutant = "drop-leak" THEN 0 ELSE IF Mutant = "drop-twice" THEN 2 ELSE 1

Init ==
    /\ slot = [o \in Objs |-> ES]
    /\ alive = [o \in Objs |-> o = 3]
    /\ maps = [c \in Cells |-> 0]
    /\ mgen = [c \in Cells |-> 0]
    /\ mappers = [o \in Objs |-> {}]
    /\ locked = [o \in Objs |-> FALSE]
    /\ sdata = [o \in Objs |-> 0]
    /\ pte = [c \in Cells |-> NoPte]
    /\ tlb = [h \in Harts |-> [c \in Cells |-> NoPte]]
    /\ uacc = [h \in Harts |-> NoUa]
    /\ rc = [f \in Frames |-> 0]
    /\ pend = [f \in Frames |-> 0]
    /\ free = Frames
    /\ content = [f \in Frames |-> 0]
    /\ ft = [h \in Harts |-> NoFault]
    /\ charge = 0
    /\ asLive = [a \in ASes |-> a = 1]
    /\ ops = 0
    /\ acq = [act |-> "none", locks |-> <<>>]

\* mmap: reserve and charge the whole request, no frame yet.
Map(c, perm) ==
    /\ ops < NumOps
    /\ asLive[AsOf(c)] /\ maps[c] = 0
    /\ ObjOf(c) = 3 \/ ~alive[ObjOf(c)]
    /\ maps' = [maps EXCEPT ![c] = perm]
    /\ mappers' = IF Mutant = "map-no-mapper" THEN mappers
                  ELSE [mappers EXCEPT ![ObjOf(c)] = @ \cup {AsOf(c)}]
    /\ alive' = [alive EXCEPT ![ObjOf(c)] = TRUE]
    /\ charge' = charge + 1
    /\ ops' = ops + 1
    /\ acq' = [act |-> "map", locks |-> <<"mm", "AS", "Obj">>]
    /\ UNCHANGED <<mgen, slot, locked, sdata, hwV, frV, ft, asLive>>

\* Remove the mappings in S. A private object dies with its only mapping and
\* hands its frame to Settle, which frees it only after the shootdown.
UnmapSet(S, act) ==
    /\ \A c \in S : maps[c] # 0
    /\ \A o \in Private : (\E c \in S : ObjOf(c) = o) => slot[o].st # "InTransit"
    /\ maps' = [c \in Cells |-> IF c \in S THEN 0 ELSE maps[c]]
    /\ mgen' = [c \in Cells |-> IF c \in S THEN mgen[c] + 1 ELSE mgen[c]]
    /\ mappers' = [o \in Objs |->
           mappers[o] \ {AsOf(c) : c \in {d \in S : ObjOf(d) = o}}]
    /\ pte' = [c \in Cells |-> IF c \in S THEN NoPte ELSE pte[c]]
    /\ tlb' = IF Mutant = "unmap-no-flush" THEN tlb
              ELSE [h \in Harts |-> [c \in Cells |->
                       IF c \in S THEN NoPte ELSE tlb[h][c]]]
    /\ slot' = [o \in Objs |->
           IF o \in Private /\ (\E c \in S : ObjOf(c) = o) THEN ES ELSE slot[o]]
    /\ alive' = [o \in Objs |->
           IF o \in Private /\ (\E c \in S : ObjOf(c) = o) THEN FALSE ELSE alive[o]]
    /\ locked' = [o \in Objs |->
           IF o \in Private /\ (\E c \in S : ObjOf(c) = o) THEN FALSE ELSE locked[o]]
    /\ pend' = [f \in Frames |-> pend[f] +
           (IF \E o \in Private : (\E c \in S : ObjOf(c) = o)
                                  /\ slot[o].st = "Frame" /\ slot[o].f = f
            THEN DropN ELSE 0)]
    /\ charge' = charge - Cardinality(S)
    /\ acq' = [act |-> act, locks |-> <<"mm", "AS", "Obj">>]
    /\ UNCHANGED <<sdata, uacc, rc, free, content, ft, ops>>

Unmap(c) ==
    /\ UnmapSet({c}, "unmap")
    /\ UNCHANGED asLive

Destroy(a) ==
    /\ asLive[a]
    /\ UnmapSet({c \in Cells : AsOf(c) = a /\ maps[c] # 0
                               /\ (Mutant # "destroy-skip-mapping" \/ ObjOf(c) = a)},
                "destroy")
    /\ asLive' = [asLive EXCEPT ![a] = FALSE]

\* fork: AS 2 gets the shared mapping and a clone of AS 1's private object.
\* Flat COW: the clone takes one refcount per frame; the parent PTE loses
\* write and the parent's TLB entries are shot down before fork returns.
Fork ==
    LET hasP == maps[<<1, 1>>] # 0
        hasS == maps[<<1, 3>>] # 0
        pc   == <<1, 1>>
    IN
    /\ ops < NumOps
    /\ asLive[1] /\ ~asLive[2]
    /\ hasP \/ hasS
    /\ hasP => slot[1].st \in {"Empty", "Frame"}
    /\ slot' = [slot EXCEPT ![2] = IF hasP THEN slot[1] ELSE ES]
    /\ alive' = [alive EXCEPT ![2] = hasP]
    /\ maps' = [maps EXCEPT ![<<2, 2>>] = IF hasP THEN maps[pc] ELSE 0,
                            ![<<2, 3>>] = IF hasS THEN maps[<<1, 3>>] ELSE 0]
    /\ mappers' = [mappers EXCEPT ![2] = IF hasP THEN {2} ELSE {},
                                  ![3] = IF hasS THEN @ \cup {2} ELSE @]
    /\ rc' = IF hasP /\ slot[1].st = "Frame"
             THEN [rc EXCEPT ![slot[1].f] = @ + 1] ELSE rc
    /\ pte' = IF hasP THEN [pte EXCEPT ![pc].writable = FALSE] ELSE pte
    /\ tlb' = IF hasP /\ Mutant # "fork-no-flush"
              THEN [h \in Harts |-> [c \in Cells |->
                       IF c = pc THEN NoPte ELSE tlb[h][c]]]
              ELSE tlb
    /\ charge' = charge + (IF hasP THEN 1 ELSE 0) + (IF hasS THEN 1 ELSE 0)
    /\ asLive' = [asLive EXCEPT ![2] = TRUE]
    /\ ops' = ops + 1
    /\ acq' = [act |-> "fork", locks |-> <<"mm", "AS", "Obj">>]
    /\ UNCHANGED <<locked, sdata, mgen, uacc, pend, free, content, ft>>

SetLocked(o) ==
    /\ alive[o] /\ ~locked[o] /\ slot[o].st \in {"Empty", "Frame"}
    /\ locked' = [locked EXCEPT ![o] = TRUE]
    /\ acq' = [act |-> "mlock", locks |-> <<"mm", "AS", "Obj">>]
    /\ UNCHANGED <<slot, alive, mappers, sdata, mapV, hwV, frV, ft, charge, asLive, ops>>

Faultable(h, c, w) ==
    /\ ft[h].st = "idle"
    /\ maps[c] # 0
    /\ w => maps[c] = 2
    /\ ~(pte[c].present /\ (~w \/ pte[c].writable))
    /\ slot[ObjOf(c)].st # "InTransit"

FaultLocks == IF Mutant = "fault-takes-mm" THEN <<"mm", "AS", "Obj">> ELSE <<"AS", "Obj">>

\* The slot already holds a frame the access may use: install under the locks.
FaultMapNow(h, c, w) ==
    LET s == slot[ObjOf(c)] IN
    /\ Faultable(h, c, w)
    /\ s.st = "Frame"
    /\ ~(w /\ rc[s.f] > 0) \/ Mutant = "cow-skip"
    /\ pte' = [pte EXCEPT ![c] = [present |-> TRUE,
                                  writable |-> w /\ (rc[s.f] = 0 \/ Mutant = "cow-skip"),
                                  f |-> s.f]]
    /\ acq' = [act |-> "fault", locks |-> FaultLocks]
    /\ UNCHANGED <<objV, mapV, tlb, uacc, frV, ft, charge, asLive, ops>>

\* Nothing usable in the slot: record the mapping epoch, drop the locks, supply.
FaultNeed(h, c, w) ==
    LET s == slot[ObjOf(c)]
        start(k, old) == ft' = [ft EXCEPT ![h] = [st |-> "looked", k |-> k, c |-> c,
                                  w |-> w, g |-> mgen[c], fr |-> 0, of |-> old]]
    IN
    /\ Faultable(h, c, w)
    /\ \/ s.st = "Empty" /\ start("zero", 0)
       \/ s.st = "Swapped" /\ start("restore", 0)
       \/ s.st = "Frame" /\ w /\ rc[s.f] > 0 /\ Mutant # "cow-skip" /\ start("cow", s.f)
    /\ acq' = [act |-> "fault", locks |-> FaultLocks]
    /\ UNCHANGED <<objV, mapV, hwV, frV, charge, asLive, ops>>

FaultSupply(h) ==
    /\ ft[h].st = "looked"
    /\ \E f \in free :
         /\ free' = free \ {f}
         /\ content' = IF ft[h].k = "zero" /\ Mutant # "no-zero"
                       THEN [content EXCEPT ![f] = 0] ELSE content
         /\ ft' = [ft EXCEPT ![h].st = "supplied", ![h].fr = f]
    /\ acq' = [act |-> "supply",
               locks |-> IF Mutant = "supply-locked" THEN <<"AS", "Obj">> ELSE <<>>]
    /\ UNCHANGED <<objV, mapV, hwV, rc, pend, charge, asLive, ops>>

\* Re-find: the mapping must be the one looked up and the slot as expected.
InstallOk(h) ==
    LET t == ft[h]
        s == slot[ObjOf(t.c)]
        slotOk == \/ t.k = "zero" /\ s.st = "Empty"
                  \/ t.k = "restore" /\ s.st = "Swapped"
                  \/ t.k = "cow" /\ s.st = "Frame" /\ s.f = t.of /\ rc[t.of] > 0
    IN /\ ft[h].st = "supplied"
       /\ slotOk
       /\ Mutant = "install-no-refind" \/ (maps[t.c] # 0 /\ mgen[t.c] = t.g)

FaultInstall(h) ==
    LET t == ft[h]
        o == ObjOf(t.c)
        c == t.c
    IN
    /\ InstallOk(h)
    /\ slot' = [slot EXCEPT ![o] = [st |-> "Frame", f |-> t.fr]]
    /\ alive' = [alive EXCEPT ![o] = TRUE]
    /\ sdata' = IF t.k = "restore" THEN [sdata EXCEPT ![o] = 0] ELSE sdata
    /\ content' = IF t.k = "cow" THEN [content EXCEPT ![t.fr] = content[t.of]]
                  ELSE IF t.k = "restore" THEN [content EXCEPT ![t.fr] = sdata[o]]
                  ELSE content
    /\ rc' = IF t.k = "cow" /\ Mutant = "cow-no-pend"
             THEN [rc EXCEPT ![t.fr] = 0, ![t.of] = @ - 1]
             ELSE [rc EXCEPT ![t.fr] = 0]
    /\ pend' = IF t.k = "cow" /\ Mutant # "cow-no-pend"
               THEN [pend EXCEPT ![t.of] = @ + 1] ELSE pend
    /\ pte' = [d \in Cells |->
           IF d = c THEN [present |-> TRUE, writable |-> t.w /\ maps[c] = 2, f |-> t.fr]
           ELSE IF t.k = "cow" /\ ObjOf(d) = o THEN NoPte ELSE pte[d]]
    /\ charge' = IF Mutant = "charge-on-fault" THEN charge + 1 ELSE charge
    /\ ft' = [ft EXCEPT ![h] = NoFault]
    /\ acq' = [act |-> "fault", locks |-> FaultLocks]
    /\ UNCHANGED <<mappers, locked, mapV, tlb, uacc, free, asLive, ops>>

FaultAbort(h) ==
    /\ ft[h].st = "supplied"
    /\ ~InstallOk(h)
    /\ free' = free \cup {ft[h].fr}
    /\ ft' = [ft EXCEPT ![h] = NoFault]
    /\ acq' = [act |-> "fault", locks |-> FaultLocks]
    /\ UNCHANGED <<objV, mapV, hwV, rc, pend, content, charge, asLive, ops>>

\* Reclaim: the PTEs go first, then the slot; the frame is held until the
\* shootdown and the readers are done.
ReclaimBegin(o) ==
    /\ slot[o].st = "Frame"
    /\ rc[slot[o].f] = 0
    /\ Mutant = "reclaim-locked" \/ ~locked[o]
    /\ slot' = [slot EXCEPT ![o] = [st |-> "InTransit", f |-> @.f]]
    /\ pte' = [c \in Cells |-> IF ObjOf(c) = o THEN NoPte ELSE pte[c]]
    /\ acq' = [act |-> "reclaim",
               locks |-> IF Mutant = "reclaim-inversion" THEN <<"Obj", "AS">>
                         ELSE <<"AS", "Obj">>]
    /\ UNCHANGED <<alive, mappers, locked, sdata, mapV, tlb, uacc, frV, ft, charge, asLive, ops>>

ReclaimStore(o) ==
    LET f == slot[o].f IN
    /\ slot[o].st = "InTransit"
    /\ Mutant = "store-early" \/ ~TlbNames(f)
    /\ ~UaccNames(f)
    /\ slot' = [slot EXCEPT ![o] = [st |-> "Swapped", f |-> 0]]
    /\ sdata' = [sdata EXCEPT ![o] = content[f]]
    /\ free' = free \cup {f}
    /\ content' = StaleOut(f)
    /\ acq' = [act |-> "store", locks |-> <<"Obj">>]
    /\ UNCHANGED <<alive, mappers, locked, mapV, hwV, rc, pend, ft, charge, asLive, ops>>

TlbFill(h, c) ==
    /\ pte[c].present /\ tlb[h][c] # pte[c]
    /\ tlb' = [tlb EXCEPT ![h][c] = pte[c]]
    /\ acq' = [act |-> "hw", locks |-> <<>>]
    /\ UNCHANGED <<objV, mapV, pte, uacc, frV, ft, charge, asLive, ops>>

UserWrite(h, c) ==
    /\ tlb[h][c].present /\ tlb[h][c].writable
    /\ content' = [content EXCEPT ![tlb[h][c].f] = 1]
    /\ acq' = [act |-> "hw", locks |-> <<>>]
    /\ UNCHANGED <<objV, mapV, hwV, rc, pend, free, ft, charge, asLive, ops>>

UaccessOpen(h, c) ==
    /\ uacc[h].f = 0 /\ pte[c].present
    /\ uacc' = [uacc EXCEPT ![h] = [f |-> pte[c].f, c |-> c]]
    /\ acq' = [act |-> "hw", locks |-> <<>>]
    /\ UNCHANGED <<objV, mapV, pte, tlb, frV, ft, charge, asLive, ops>>

UaccessClose(h) ==
    /\ uacc[h].f # 0
    /\ uacc' = [uacc EXCEPT ![h] = NoUa]
    /\ acq' = [act |-> "hw", locks |-> <<>>]
    /\ UNCHANGED <<objV, mapV, pte, tlb, frV, ft, charge, asLive, ops>>

\* The IPI round: runs with no lock held.
Shootdown(f) ==
    /\ Flushable(f)
    /\ tlb' = [h \in Harts |-> [c \in Cells |->
                 IF tlb[h][c].f = f THEN NoPte ELSE tlb[h][c]]]
    /\ acq' = [act |-> "shootdown",
               locks |-> IF Mutant = "shootdown-locked" THEN <<"AS", "Obj">> ELSE <<>>]
    /\ UNCHANGED <<objV, mapV, pte, uacc, frV, ft, charge, asLive, ops>>

\* Apply the deferred refcount decrement; free the frame at zero holders, only
\* once no TLB entry, PTE or open user copy names it through a dropped reference.
Settle(f) ==
    /\ pend[f] > 0
    /\ Mutant = "free-early" \/ ~StaleTlb(f)
    /\ Mutant = "uaccess-skip" \/ ~StaleUacc(f)
    /\ ~StalePte(f)
    /\ pend' = [pend EXCEPT ![f] = 0]
    /\ IF N(f) = 0
       THEN /\ free' = free \cup {f}
            /\ rc' = [rc EXCEPT ![f] = 0]
            /\ content' = StaleOut(f)
       ELSE /\ rc' = [rc EXCEPT ![f] = rc[f] - pend[f]]
            /\ UNCHANGED <<free, content>>
    /\ acq' = [act |-> "settle", locks |-> <<>>]
    /\ UNCHANGED <<objV, mapV, hwV, ft, charge, asLive, ops>>

Next ==
    \/ \E c \in Cells, p \in 1..2 : Map(c, p)
    \/ \E c \in Cells : Unmap(c)
    \/ \E a \in ASes : Destroy(a)
    \/ Fork
    \/ \E o \in Objs : SetLocked(o)
    \/ \E h \in Harts, c \in Cells, w \in BOOLEAN : FaultMapNow(h, c, w) \/ FaultNeed(h, c, w)
    \/ \E h \in Harts : FaultSupply(h) \/ FaultInstall(h) \/ FaultAbort(h)
    \/ \E o \in Objs : ReclaimBegin(o) \/ ReclaimStore(o)
    \/ \E h \in Harts, c \in Cells : TlbFill(h, c) \/ UserWrite(h, c) \/ UaccessOpen(h, c)
    \/ \E h \in Harts : UaccessClose(h)
    \/ \E f \in Frames : Shootdown(f) \/ Settle(f)

Spec == Init /\ [][Next]_vars

\* ---------------------------------------------------------------------
\* Invariants
\* ---------------------------------------------------------------------

PteSet == [present: BOOLEAN, writable: BOOLEAN, f: 0..NumFrames]

TypeOK ==
    /\ slot \in [Objs -> [st: {"Empty", "Frame", "InTransit", "Swapped"},
                          f: 0..NumFrames]]
    /\ alive \in [Objs -> BOOLEAN]
    /\ maps \in [Cells -> 0..2]
    /\ mgen \in [Cells -> Nat]
    /\ mappers \in [Objs -> SUBSET ASes]
    /\ locked \in [Objs -> BOOLEAN]
    /\ sdata \in [Objs -> 0..2]
    /\ pte \in [Cells -> PteSet]
    /\ tlb \in [Harts -> [Cells -> PteSet]]
    /\ uacc \in [Harts -> [f: 0..NumFrames, c: Cells]]
    /\ rc \in [Frames -> Nat]
    /\ pend \in [Frames -> Nat]
    /\ free \subseteq Frames
    /\ content \in [Frames -> 0..2]
    /\ ft \in [Harts -> [st: {"idle", "looked", "supplied"},
                         k: {"none", "zero", "restore", "cow"},
                         c: Cells, w: BOOLEAN, g: Nat,
                         fr: 0..NumFrames, of: 0..NumFrames]]
    /\ charge \in Nat
    /\ asLive \in [ASes -> BOOLEAN]
    /\ ops \in 0..NumOps
    /\ Len(acq.locks) <= 3
    /\ \A i \in 1..Len(acq.locks) : acq.locks[i] \in LockNames

\* 1: a PTE never says more than the slot; writable needs a writable mapping
\* and a sole holder.
PteIsCache ==
    \A c \in Cells : pte[c].present =>
        /\ slot[ObjOf(c)].st = "Frame" /\ slot[ObjOf(c)].f = pte[c].f
        /\ pte[c].writable => (maps[c] = 2 /\ rc[pte[c].f] = 0)

\* 1: a cached writable translation never outlives sole ownership (the stale
\* writable entry that fork or a COW break must shoot down).
TlbWritableImpliesSole ==
    \A h \in Harts, c \in Cells :
        (tlb[h][c].present /\ tlb[h][c].writable) => rc[tlb[h][c].f] = 0

\* 2: refcount counts the slots naming the frame, less one, released
\* references included until they settle.
RefIsHolders ==
    \A f \in Frames : (N(f) + pend[f] > 0) => rc[f] + 1 = N(f) + pend[f]

\* 3
NoFreeWhileNamed ==
    \A f \in free :
        /\ N(f) = 0 /\ pend[f] = 0
        /\ \A c \in Cells : pte[c].f # f
        /\ \A h \in Harts : uacc[h].f # f /\ ft[h].fr # f
        /\ \A h \in Harts, c \in Cells : tlb[h][c].f # f

\* 4: nothing is cached or installed for a mapping that was removed.
NoInstallAfterRelease ==
    \A c \in Cells : maps[c] = 0 =>
        /\ ~pte[c].present
        /\ \A h \in Harts : ~tlb[h][c].present

\* 5
ZeroOnFirstUse ==
    \A o \in Objs : slot[o].st = "Frame" => content[slot[o].f] # 2

\* 6
MapperIsReverse ==
    \A o \in Objs :
        mappers[o] = {AsOf(c) : c \in {d \in Cells : ObjOf(d) = o /\ maps[d] # 0}}

\* 7: the charge moves on map and unmap only, never on a fault.
ChargeAtReserve ==
    charge = Cardinality({c \in Cells : maps[c] # 0})

\* 8: every frame is in exactly one place.
FrameAccounted ==
    \A f \in Frames :
        (IF f \in free THEN 1 ELSE 0)
        + (IF N(f) + pend[f] > 0 THEN 1 ELSE 0)
        + Cardinality({h \in Harts : ft[h].fr = f}) = 1

\* 8
DestroyLeavesNothing ==
    \A a \in ASes : ~asLive[a] =>
        /\ \A c \in Cells : AsOf(c) = a => maps[c] = 0
        /\ ~alive[a]

\* 13
LockedNeverReclaimed ==
    \A o \in Objs : locked[o] => slot[o].st \in {"Empty", "Frame"}

\* A stale TLB entry whose slot no longer names the frame is covered by a
\* pending released reference.
TlbNamesSlotOrPending ==
    \A h \in Harts, c \in Cells :
        tlb[h][c].present =>
            (SlotNames(ObjOf(c), tlb[h][c].f) \/ pend[tlb[h][c].f] > 0)

\* 2.10
LockOrder ==
    \A i, j \in 1..Len(acq.locks) :
        i < j => Rank[acq.locks[i]] < Rank[acq.locks[j]]

SupplyUnlocked == acq.act = "supply" => acq.locks = <<>>

ShootdownAfterRelease == acq.act = "shootdown" => acq.locks = <<>>

FaultNeverTakesMm ==
    acq.act = "fault" => \A i \in 1..Len(acq.locks) : acq.locks[i] # "mm"

=============================================================================
