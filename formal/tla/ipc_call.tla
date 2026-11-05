------------------------------ MODULE ipc_call ------------------------------
(*
The IPC call record of the one call family (rfcs/c2-one-dispatch-design.md 2.3
and 4.3, C2-8; crates/core/ipc/src/ep_queue.rs, fastcall.rs): a caller's call
is Queued on the endpoint, Accepted by a server (or refused there), then
Replied, or Cancelled (timeout, PEERDIED, REVOKED, kill). A call comes in one
of two forms: the register form (up to four words, no capability, no deadline)
or the descriptor form (a MsgDesc: more words, capabilities, a deadline). An
accept has the same two forms. A register-form accept names four words and
one capability: it takes a descriptor-form call that fits them ("desc") and
refuses one that does not ("big", -EMSGFORM): the server sees nothing and
every capability the call carried is back with the caller. A server may delegate the
call's reply warrant once (REPLY_DELEGATE): the new holder answers it, the old
one no longer can. The invariants:

  OneOutcome     every call reaches exactly one terminal outcome
  EdgeOnce       the call's wait-graph edge is held while the call is live
                 and released exactly once on every terminal path
  ReplyOnce      a call is answered at most once, delegated or not
  FormRespected  a register-form accept never holds a call its registers
                 cannot name
  CapsHome       a call's capabilities are in flight while it is queued, back
                 with the caller after a refusal or a cancel of a queued call,
                 and with the server once it accepted

MODEL VS CODE: 2 callers, one endpoint, one server task and one delegate (the
transport proxy of `ep_queue::delegate`). Each caller has one call record (one
outstanding call per task, as the record per task slot). A transition is
atomic, as under the endpoint queue's lock; the edge's two halves (the
replier's retire and the caller's leave, fastcall.rs) are one release here.
NumOps bounds the actions. Mutant selects one injected defect; every
ipc_call_mut_*.cfg must be rejected for the invariant on its `expect:` line.
*)

EXTENDS Integers

CONSTANTS NumOps, Mutant

Mutants == {"none", "reg-accepts-big", "cancel-after-reply", "reply-after-cancel",
            "old-holder-replies", "refusal-keeps-caps"}

Callers == {1, 2}
Forms   == {"reg", "desc", "big"}
Accepts == {"reg", "desc"}
Live    == {"queued", "accepted"}
Ended   == {"replied", "done"}

VARIABLES st, form, af, holder, delegated, rel, term, rep, caps, why, ops

vars == <<st, form, af, holder, delegated, rel, term, rep, caps, why, ops>>

TypeOK ==
    /\ st \in [Callers -> {"idle"} \cup Live \cup Ended]
    /\ form \in [Callers -> Forms]
    /\ af \in [Callers -> {"none"} \cup Accepts]
    /\ holder \in [Callers -> {"none", "server", "proxy"}]
    /\ delegated \in [Callers -> BOOLEAN]
    /\ rel \in [Callers -> 0..3]
    /\ term \in [Callers -> 0..3]
    /\ rep \in [Callers -> 0..3]
    /\ caps \in [Callers -> {"none", "caller", "flight", "server"}]
    /\ why \in [Callers -> {"none", "reply", "msgform", "cancel-queued", "cancel-accepted"}]
    /\ ops \in 0..NumOps

Init ==
    /\ st = [c \in Callers |-> "idle"]
    /\ form = [c \in Callers |-> "reg"]
    /\ af = [c \in Callers |-> "none"]
    /\ holder = [c \in Callers |-> "none"]
    /\ delegated = [c \in Callers |-> FALSE]
    /\ rel = [c \in Callers |-> 0]
    /\ term = [c \in Callers |-> 0]
    /\ rep = [c \in Callers |-> 0]
    /\ caps = [c \in Callers |-> "none"]
    /\ why = [c \in Callers |-> "none"]
    /\ ops = 0

Step == ops < NumOps /\ ops' = ops + 1

\* A terminal transition: the outcome is taken and the edge released.
Finish(c, s, w) ==
    /\ st' = [st EXCEPT ![c] = s]
    /\ why' = [why EXCEPT ![c] = w]
    /\ term' = [term EXCEPT ![c] = @ + 1]
    /\ rel' = [rel EXCEPT ![c] = @ + 1]

\* A new call: the edge to the server is taken, a descriptor call's
\* capabilities leave the caller's table.
Call(c, f) ==
    /\ st[c] = "idle"
    /\ st' = [st EXCEPT ![c] = "queued"]
    /\ form' = [form EXCEPT ![c] = f]
    /\ caps' = [caps EXCEPT ![c] = IF f = "reg" THEN "none" ELSE "flight"]
    /\ af' = [af EXCEPT ![c] = "none"]
    /\ holder' = [holder EXCEPT ![c] = "none"]
    /\ delegated' = [delegated EXCEPT ![c] = FALSE]
    /\ rel' = [rel EXCEPT ![c] = 0]
    /\ term' = [term EXCEPT ![c] = 0]
    /\ rep' = [rep EXCEPT ![c] = 0]
    /\ why' = [why EXCEPT ![c] = "none"]

\* The server takes a queued call with an accept of form `a`.
Accept(c, a) ==
    /\ st[c] = "queued"
    /\ IF a = "reg" /\ form[c] = "big" /\ Mutant # "reg-accepts-big"
       THEN \* -EMSGFORM: the server sees nothing, the capabilities go back.
            /\ Finish(c, "done", "msgform")
            /\ caps' = [caps EXCEPT ![c] = IF Mutant = "refusal-keeps-caps" THEN "flight" ELSE "caller"]
            /\ UNCHANGED <<form, af, holder, delegated, rep>>
       ELSE /\ st' = [st EXCEPT ![c] = "accepted"]
            /\ af' = [af EXCEPT ![c] = a]
            /\ holder' = [holder EXCEPT ![c] = "server"]
            /\ caps' = [caps EXCEPT ![c] = IF form[c] = "reg" THEN "none" ELSE "server"]
            /\ UNCHANGED <<form, delegated, rel, term, rep, why>>

\* The holder of the reply warrant moves it to the proxy, once.
Delegate(c) ==
    /\ st[c] = "accepted" /\ holder[c] = "server" /\ ~delegated[c]
    /\ holder' = [holder EXCEPT ![c] = "proxy"]
    /\ delegated' = [delegated EXCEPT ![c] = TRUE]
    /\ UNCHANGED <<st, form, af, rel, term, rep, caps, why>>

\* `h` answers the call. Only the warrant's holder may, and only while the
\* call is live; an answer to an ended call is stale and changes nothing.
Reply(c, h) ==
    /\ \/ st[c] = "accepted" /\ holder[c] = h
       \/ Mutant = "reply-after-cancel" /\ st[c] = "done" /\ holder[c] = h
       \/ Mutant = "old-holder-replies" /\ h = "server" /\ delegated[c] /\ st[c] \in {"accepted", "replied"}
    /\ rep' = [rep EXCEPT ![c] = @ + 1]
    /\ IF st[c] = "accepted"
       THEN Finish(c, "replied", "reply")
       ELSE /\ st' = [st EXCEPT ![c] = "replied"]
            /\ term' = [term EXCEPT ![c] = @ + 1]
            /\ UNCHANGED <<rel, why>>
    /\ UNCHANGED <<form, af, holder, delegated, caps>>

\* Timeout, PEERDIED, REVOKED or a kill ends a live call. A queued call's
\* capabilities go back; an accepted call's stay with the server.
Cancel(c) ==
    /\ \/ st[c] \in Live
       \/ Mutant = "cancel-after-reply" /\ st[c] = "replied"
    /\ Finish(c, "done", IF st[c] = "queued" THEN "cancel-queued" ELSE "cancel-accepted")
    /\ caps' = [caps EXCEPT ![c] = IF st[c] = "queued" /\ form[c] # "reg" THEN "caller" ELSE @]
    /\ UNCHANGED <<form, af, holder, delegated, rep>>

\* The caller takes the outcome; its record is free for the next call.
Collect(c) ==
    /\ st[c] \in Ended
    /\ st' = [st EXCEPT ![c] = "idle"]
    /\ UNCHANGED <<form, af, holder, delegated, rel, term, rep, caps, why>>

Next ==
    \E c \in Callers :
        /\ Step
        /\ \/ \E f \in Forms : Call(c, f)
           \/ \E a \in Accepts : Accept(c, a)
           \/ Delegate(c)
           \/ \E h \in {"server", "proxy"} : Reply(c, h)
           \/ Cancel(c)
           \/ Collect(c)

Spec == Init /\ [][Next]_vars

OneOutcome == \A c \in Callers :
    /\ term[c] <= 1
    /\ (st[c] \in Ended => term[c] = 1)

EdgeOnce == \A c \in Callers :
    /\ rel[c] <= 1
    /\ (st[c] \in Live => rel[c] = 0)
    /\ (st[c] \in Ended => rel[c] = 1)

ReplyOnce == \A c \in Callers : rep[c] <= 1

FormRespected == \A c \in Callers :
    st[c] = "accepted" => ~(af[c] = "reg" /\ form[c] = "big")

CapsHome == \A c \in Callers :
    /\ (form[c] = "reg" => caps[c] = "none")
    /\ (form[c] # "reg" /\ st[c] = "queued" => caps[c] = "flight")
    /\ (form[c] # "reg" /\ why[c] \in {"msgform", "cancel-queued"} => caps[c] = "caller")
    /\ (form[c] # "reg" /\ st[c] = "accepted" => caps[c] = "server")

=============================================================================
