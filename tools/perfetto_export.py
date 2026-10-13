#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""Export the flight recorder, the decision records and a kernel trace as one
Perfetto / Chrome trace-event JSON, so "what did the machine decide, and what
was it doing at that moment" is one timeline.

usage: perfetto_export.py [--recorder LOGNNNNN.BIN ...] [--decisions FILE ...]
                          [--trace FILE ...] [--hz TICKS_PER_SECOND] -o out.json
       perfetto_export.py --self-test

Inputs (any mix; every one optional, at least one needed):

  --recorder FILE   a flight-recorder file from the volume (`/LOG/LOGnnnnn.BIN`):
                    a 16-byte header (`RBL1`, version) and 32-byte records
                    `[ts u64][kind u8][flags u8][pad u16][payload 20]`
                    (crates/core/actuation/src/logger.rs). `ts` is raw timebase
                    ticks, so `--hz` is needed to place them (default
                    10 000 000, QEMU virt riscv64). A safety record is named by
                    its violation code; a durable decision receipt (codes 0x1B
                    base, 0x1C extension) is decoded to its rule, verdict,
                    subject and numbers.
  --decisions FILE  the decisions the kernel holds, either `cat /proc/decisions`
                    saved as text (DECISION_RECORDS_DEV) or `/proc/decisions.bin`
                    saved raw (104-byte `ProvenanceRecord` records, the ring or
                    the journal of durable decisions; the file name ends in
                    `.bin`). Placed by the record's `clock` (nanoseconds); a
                    text line without one (an older kernel) is spaced one
                    microsecond per id and marked `clock: none`.
  --trace FILE      `tracectl stream` text output (`[cpuN] SEC.NANOS event
                    key=value ...`), placed by its own clock.

Time: the trace and the decisions are nanoseconds on the kernel's timebase
since boot; the recorder is converted with `--hz`. Output timestamps are
microseconds (the trace-event unit), kept fractional.

Tracks: process 1 "kernel trace" (one thread per CPU), process 2 "decisions"
(one thread per rule), process 3 "flight recorder" (one thread per record
kind). Every record is an instant event; its arguments are the fields.

The tables below (rules, verdicts, safety codes) are the kernel's. `--self-test`
checks them against crates/core/decision/src/lib.rs and
crates/core/actuation/src/logger.rs when run from a checkout, and exercises
every decoder on records built here (the gate's `perfetto_export` row runs it).
"""
import json
import os
import re
import struct
import sys

# ── the kernel's tables ──────────────────────────────────────────────────────

# `azos_decision::RULES` order (crates/core/decision/src/lib.rs).
RULES = ["deadline-admission", "rt-band-cap", "memory-admission", "wake-placement",
         "cap-denial", "deadline-expired", "split-lock", "cap-derive", "cap-revoke", "neverallow",
         "device-admission", "irq-budget", "placement", "package-install"]
# `azos_decision::VERDICTS`.
VERDICTS = ["admit", "refuse", "place", "deny"]
# `azos_decision::REFUSAL_REASONS`.
REASONS = ["none", "malformed", "no-room", "band-cap", "busy", "levels", "class-off"]
# Fields of a rule's three numbers (`RuleInfo::fields`); "boot|run-time" pairs
# are split on `|`: the run-time form (a reason in the third number's high
# half) takes the second name.
FIELDS = {
    "deadline-admission": (["placed", "rows", "-"], ["runtime_us", "period_us", "available_us"]),
    "rt-band-cap": (["placed", "cap_pct", "-"], None),
    "memory-admission": (["need_pages", "free_pages", "reserve_pages"], None),
    "wake-placement": (["cpu", "last_cpu", "prio"], None),
    "cap-denial": (["kind", "reason", "dropped"], None),
    "deadline-expired": (["deadline_ns", "now_ns", "clock"], None),
    "split-lock": (["rip", "cpu", "-"], None),
    "cap-derive": (["-", "-", "expiry_ns"], None),
    "cap-revoke": (["-", "-", "descendant"], None),
    "neverallow": (["rule", "kind", "grant"], None),
    "irq-budget": (["line", "masked", "overruns"], None),
    "placement": (["move", "measured_ns", "limit_ns"], None),
    "package-install": (["images", "signer", "reason"], None),
}
# logger.rs: `LOG_EVT_*` kinds and the `SAFETY_*` violation codes.
EVENTS = {1: "sensor_snapshot", 2: "actuator_cmd", 3: "safety_violation", 4: "mode_change",
          5: "skill_start", 6: "skill_end", 7: "waypoint", 8: "error"}
SAFETY = {0x01: "envelope_refused", 0x02: "estop", 0x03: "degrade", 0x04: "cap_denied",
          0x05: "log_wrapped", 0x06: "semantic_level", 0x07: "semantic_malformed",
          0x08: "unknown_pkt", 0x09: "estop_pin_invalid", 0x0A: "cap_denied_typed",
          0x0B: "cap_denied_suppressed", 0x0C: "seccomp_audit", 0x0D: "exec_refused",
          0x0E: "cap_seed_refused", 0x0F: "cow_oom", 0x10: "actuation_gate_absent",
          0x11: "release_nonce", 0x12: "sensor_incoherent", 0x13: "payload_refused",
          0x14: "entropy_unseeded_refused", 0x15: "service_refused", 0x16: "topo_class_refused",
          0x17: "driver_supervisor", 0x18: "ml_absent", 0x19: "rt_watchdog", 0x1A: "topo_source",
          0x1B: "decision_refused", 0x1C: "decision_provenance"}
DECISION_BASE, DECISION_EXT = 0x1B, 0x1C

LOG_HEADER = 16
LOG_RECORD = 32
PROV_SIZE = 104
# rule u8, verdict u8, pad, subject u32, seq u64, cap_slot 2xu64, parent_cap 2xu64,
# topology_row u32, node u32, image_hash u64, session u64, n 3xu64, clock_ns u64.
PROV = struct.Struct("<BBxxIQ2Q2QIIQQ3QQ")
assert PROV.size == PROV_SIZE

PID_TRACE, PID_DECISIONS, PID_RECORDER = 1, 2, 3


class ExportError(Exception):
    pass


# ── decoders ─────────────────────────────────────────────────────────────────

def rule_name(i):
    return RULES[i] if i < len(RULES) else f"rule{i}"


def verdict_name(i):
    return VERDICTS[i] if i < len(VERDICTS) else f"verdict{i}"


def numbers(rule, verdict, n):
    """The three numbers of a decision by name, as `RuleInfo::fields` names them."""
    name = rule_name(rule)
    boot, run = FIELDS.get(name, (["n0", "n1", "n2"], None))
    args = {}
    if run is not None and verdict == 1 and (n[2] >> 32) != 0:
        # A run-time reservation's refusal packs the reason above bit 32.
        reason = n[2] >> 32
        args.update({run[0]: n[0], run[1]: n[1], run[2]: n[2] & 0xFFFFFFFF,
                     "reason": REASONS[reason] if reason < len(REASONS) else reason})
        return args
    for k, v in zip(boot, n):
        if k == "-" or (k == "dropped" and v == 0):
            continue
        args[k] = v
    return args


def decode_provenance(buf):
    """The `ProvenanceRecord`s in a `/proc/decisions.bin` dump."""
    out = []
    for off in range(0, len(buf) - PROV_SIZE + 1, PROV_SIZE):
        (rule, verdict, subject, seq, c0, c1, p0, p1, row, node, image, session,
         n0, n1, n2, clock) = PROV.unpack_from(buf, off)
        if seq == 0:
            continue
        out.append({"seq": seq, "rule": rule, "verdict": verdict, "subject": subject,
                    "n": (n0, n1, n2), "clock_ns": clock, "cap_slot": c1 << 64 | c0,
                    "parent_cap": p1 << 64 | p0, "topology_row": row, "node": node,
                    "image_hash_prefix": image, "session": session})
    return out


TEXT_LINE = re.compile(r'^(\d+) ([a-z-]+) (admit|refuse|place|deny) (\S+?)=(\d+)(.*?)( rejected="(.*)")?$')
KV = re.compile(r'(\w+)=(\S+)')


def decode_text(text):
    """The decisions in `cat /proc/decisions` (lines `SEQ RULE VERDICT SUBJECT=V k=v ...`)."""
    out = []
    for line in text.splitlines():
        m = TEXT_LINE.match(line.strip())
        if not m:
            continue
        seq, rule, verdict, sname, subject, rest, _, rejected = m.groups()
        kv = {k: v for k, v in KV.findall(rest)}
        clock = int(kv.pop("clock", 0))
        out.append({"seq": int(seq), "rule": RULES.index(rule) if rule in RULES else 255,
                    "verdict": VERDICTS.index(verdict), "subject": int(subject),
                    "subject_name": sname, "fields": kv, "clock_ns": clock,
                    "rejected": rejected or ""})
    out.sort(key=lambda d: d["seq"])
    return out


def decode_recorder(buf):
    """`(ts_ticks, kind, flags, payload)` of each record of a recorder file."""
    if len(buf) < LOG_HEADER or buf[:4] != b"RBL1":
        raise ExportError("not a flight-recorder file (no RBL1 header)")
    out = []
    for off in range(LOG_HEADER, len(buf) - LOG_RECORD + 1, LOG_RECORD):
        ts, kind, flags = struct.unpack_from("<QBB", buf, off)
        out.append((ts, kind, flags, bytes(buf[off + 12: off + 32])))
    return out


def decode_receipt(payload):
    """A durable decision receipt (`compact_base`): rule, verdict, subject, numbers."""
    rule, verdict = payload[1], payload[2]
    hi = payload[3]
    subject = struct.unpack_from("<I", payload, 4)[0]
    n0, n1, lo = struct.unpack_from("<III", payload, 8)
    return rule, verdict, subject, (n0, n1, lo | hi << 32)


def decode_trace(text):
    """`tracectl stream` lines: `(ns, cpu, event, args)`."""
    out = []
    pat = re.compile(r'^\[cpu(\d+)\]\s+(\d+)(?:\.(\d{1,9}))?\s+(\S+)(.*)$')
    for line in text.splitlines():
        m = pat.match(line.strip())
        if not m:
            continue
        cpu, sec, frac, ev, rest = m.groups()
        ns = int(sec) * 1_000_000_000 + (int((frac or "0").ljust(9, "0")) if frac is not None else 0)
        if frac is None:
            ns = int(sec)  # a raw tick count: tracectl printed no clock rate
        out.append((ns, int(cpu), ev, {k: v for k, v in KV.findall(rest)}))
    return out


# ── the trace-event JSON ─────────────────────────────────────────────────────

def meta(pid, tid, kind, name):
    return {"ph": "M", "pid": pid, "tid": tid, "name": kind, "args": {"name": name}}


def instant(name, cat, ts_us, pid, tid, args):
    return {"name": name, "cat": cat, "ph": "i", "s": "t", "ts": ts_us, "pid": pid, "tid": tid, "args": args}


def export(recorders=(), decisions=(), traces=(), hz=10_000_000):
    """The trace-event dict for the given file contents: recorders (bytes),
    decisions (`(name, bytes)`), traces (text)."""
    ev = []
    if recorders:
        ev.append(meta(PID_RECORDER, 0, "process_name", "flight recorder"))
        seen = set()
    for buf in recorders:
        pending = None
        for ts, kind, flags, payload in decode_recorder(buf):
            us = ts * 1_000_000 / hz
            if kind == 3 and payload[0] in (DECISION_BASE, DECISION_EXT):
                if payload[0] == DECISION_BASE:
                    rule, verdict, subject, n = decode_receipt(payload)
                    pending = (rule, verdict, subject)
                    args = {"rule": rule_name(rule), "verdict": verdict_name(verdict), "subject": subject,
                            **numbers(rule, verdict, n)}
                    name = f"decision {rule_name(rule)} {verdict_name(verdict)}"
                else:
                    r, v, s = payload[1], payload[2], struct.unpack_from("<I", payload, 4)[0]
                    image, row = struct.unpack_from("<QI", payload, 8)
                    args = {"rule": rule_name(r), "verdict": verdict_name(v), "subject": s,
                            "image_hash_prefix": f"{image:016x}", "topology_row": row,
                            "belongs_to_previous": pending == (r, v, s)}
                    name = "decision provenance"
                tid = 100 + kind
                cat = "decision-receipt"
            elif kind == 3:
                code = payload[0]
                name = f"safety {SAFETY.get(code, hex(code))}"
                args = {"code": code, "action": payload[1], "detail": struct.unpack_from("<I", payload, 4)[0]}
                tid, cat = 100 + kind, "safety"
            else:
                name = EVENTS.get(kind, f"event{kind}")
                args = {"payload": payload.hex()}
                tid, cat = 100 + kind, "recorder"
            if tid not in seen:
                seen.add(tid)
                ev.append(meta(PID_RECORDER, tid, "thread_name", EVENTS.get(kind, f"event{kind}")))
            args["flags"] = flags
            ev.append(instant(name, cat, us, PID_RECORDER, tid, args))
    if decisions:
        ev.append(meta(PID_DECISIONS, 0, "process_name", "decisions"))
        for r in range(len(RULES)):
            ev.append(meta(PID_DECISIONS, r + 1, "thread_name", rule_name(r)))
    for name, buf in decisions:
        recs = decode_provenance(buf) if name.endswith(".bin") else decode_text(buf.decode("utf-8", "replace"))
        for d in recs:
            args = {"id": d["seq"], "verdict": verdict_name(d["verdict"]), "subject": d["subject"]}
            if "n" in d:
                args.update(numbers(d["rule"], d["verdict"], d["n"]))
                for k in ("cap_slot", "parent_cap"):
                    if d[k]:
                        args[k] = f"{d[k]:032x}"
                for k in ("topology_row", "node", "session"):
                    if d[k]:
                        args[k] = d[k]
                if d["image_hash_prefix"]:
                    args["image_hash_prefix"] = f"{d['image_hash_prefix']:016x}"
            else:
                args.update(d["fields"])
                if d["rejected"]:
                    args["rejected"] = d["rejected"]
            if d["clock_ns"]:
                us = d["clock_ns"] / 1000
            else:
                us = d["seq"]  # no clock: one microsecond per id
                args["clock"] = "none"
            tid = d["rule"] + 1 if d["rule"] < len(RULES) else len(RULES) + 1
            ev.append(instant(f"{rule_name(d['rule'])} {verdict_name(d['verdict'])}", "decision", us,
                              PID_DECISIONS, tid, args))
    if traces:
        ev.append(meta(PID_TRACE, 0, "process_name", "kernel trace"))
        cpus = set()
    for text in traces:
        for ns, cpu, event, args in decode_trace(text):
            if cpu not in cpus:
                cpus.add(cpu)
                ev.append(meta(PID_TRACE, cpu + 1, "thread_name", f"cpu{cpu}"))
            ev.append(instant(event, "trace", ns / 1000, PID_TRACE, cpu + 1, args))
    if not ev:
        raise ExportError("nothing to export: give --recorder, --decisions or --trace")
    # Metadata first, then by time (stable for equal stamps).
    ev.sort(key=lambda e: (e["ph"] != "M", e.get("ts", 0)))
    return {"traceEvents": ev, "displayTimeUnit": "ns"}


# ── self-test ────────────────────────────────────────────────────────────────

def _rust_list(src, anchor, pat):
    i = src.index(anchor)
    return re.findall(pat, src[i:i + 6000])


def check_tables(root):
    """The tables above against the kernel's sources (a checkout's)."""
    dec = open(os.path.join(root, "crates/core/decision/src/lib.rs")).read()
    names = _rust_list(dec, "pub const RULES", r'name: "([a-z-]+)"')[:len(RULES)]
    assert names == RULES, f"rules differ from decision/src/lib.rs: {names}"
    vs = re.search(r'pub const VERDICTS: \[&str; \d+\] = (\[[^\]]*\])', dec).group(1)
    assert json.loads(vs) == VERDICTS, f"verdicts differ: {vs}"
    rr = re.search(r'pub const REFUSAL_REASONS: \[&str; \d+\] =\s*(\[[^\]]*\])', dec).group(1)
    assert json.loads(rr) == REASONS, f"refusal reasons differ: {rr}"
    log = open(os.path.join(root, "crates/core/actuation/src/logger.rs")).read()
    codes = {int(v, 16): k.lower()[len("safety_"):] for k, v in
             re.findall(r'pub const (SAFETY_[A-Z0-9_]+): u8 = (0x[0-9A-Fa-f]+);', log)}
    for c, n in SAFETY.items():
        assert codes.get(c) == n, f"safety code {c:#x}: tool {n!r}, logger.rs {codes.get(c)!r}"
    kinds = {int(v, 16): k.lower()[len("log_evt_"):] for k, v in
             re.findall(r'pub const (LOG_EVT_[A-Z_]+): u8 = (0x[0-9A-Fa-f]+);', log)}
    for k, n in EVENTS.items():
        assert kinds.get(k) == n, f"event {k}: tool {n!r}, logger.rs {kinds.get(k)!r}"
    assert f"pub const SIZE: usize = {PROV_SIZE};" in open(
        os.path.join(root, "crates/core/decision/src/prov.rs")).read(), "ProvenanceRecord size differs"


def prov_bytes(rule, verdict, subject, seq, n, clock, **kw):
    return PROV.pack(rule, verdict, subject, seq, kw.get("cap", 0), 0, kw.get("parent", 0), 0,
                     kw.get("row", 0), 0, kw.get("image", 0), 0, *n, clock)


def receipt(rule, verdict, subject, n):
    """`azos_decision::compact_base`."""
    sat = lambda v: min(v, 0xFFFFFFFF)
    return bytes([DECISION_BASE, rule, verdict, (n[2] >> 32) & 0xFF]) + struct.pack(
        "<IIII", subject, sat(n[0]), sat(n[1]), n[2] & 0xFFFFFFFF)


def log_record(ts, kind, payload):
    return struct.pack("<QBBH", ts, kind, 0, 0) + payload.ljust(20, b"\0")


def self_test(root=None):
    if root:
        check_tables(root)
    # A refused reservation, as the kernel exports it, becomes one instant with
    # its numbers by name and the reason named.
    b = prov_bytes(0, 1, 7, 12, (500, 1000, 2 << 32 | 40), 3_000_000_000)
    t = export(decisions=[("decisions.bin", b)])
    d = [e for e in t["traceEvents"] if e["ph"] == "i"]
    assert len(d) == 1 and d[0]["ts"] == 3_000_000.0, d
    a = d[0]["args"]
    assert (a["id"], a["runtime_us"], a["period_us"], a["available_us"], a["reason"]) == (12, 500, 1000, 40, "no-room"), a
    # A boot admission keeps its own names.
    t = export(decisions=[("d.bin", prov_bytes(0, 0, 4, 1, (2, 5, 0), 10_000))])
    a = [e for e in t["traceEvents"] if e["ph"] == "i"][0]["args"]
    assert (a["placed"], a["rows"]) == (2, 5) and "runtime_us" not in a, a
    # The text form, with and without a clock.
    txt = ("# 2 decisions since boot, ring 64, newest first\n"
           '2 cap-denial deny tid=9 kind=1 reason=2 clock=5000 rejected="grant: the handle is stale"\n'
           '1 deadline-admission refuse tid=7 runtime_us=500 period_us=1000 reason<<32+available_us=8589934592 rejected="run the rows"\n')
    t = export(decisions=[("decisions.txt", txt.encode())])
    d = sorted((e for e in t["traceEvents"] if e["ph"] == "i"), key=lambda e: e["args"]["id"])
    assert [e["args"]["id"] for e in d] == [1, 2] and d[1]["ts"] == 5.0 and d[0]["args"]["clock"] == "none", d
    assert d[1]["args"]["kind"] == "1" and d[1]["args"]["rejected"].startswith("grant"), d[1]
    # The recorder: a header, a safety record and a durable receipt with its extension.
    base = receipt(0, 1, 7, (500, 1000, 2 << 32 | 40))
    ext = bytes([DECISION_EXT, 0, 1, 0]) + struct.pack("<IQI", 7, 0xFEED, 3)
    f = b"RBL1" + bytes(12) + log_record(20_000_000, 3, bytes([0x02, 1, 0, 0, 9, 0, 0, 0])) \
        + log_record(30_000_000, 3, base) + log_record(30_000_001, 3, ext)
    t = export(recorders=[f], hz=10_000_000)
    r = [e for e in t["traceEvents"] if e["ph"] == "i"]
    assert [e["name"] for e in r] == ["safety estop", "decision deadline-admission refuse", "decision provenance"], r
    assert r[0]["ts"] == 2_000_000.0 and r[1]["args"]["runtime_us"] == 500, r
    assert r[2]["args"]["belongs_to_previous"] and r[2]["args"]["topology_row"] == 3, r[2]
    # The trace.
    tr = "[cpu1] 0.000001500 sched_switch prev=3 next=4 reason=preempted\nnoise\n[cpu0] 2.000000000 irq_entry irq=5\n"
    t = export(traces=[tr])
    i = [e for e in t["traceEvents"] if e["ph"] == "i"]
    assert [(e["tid"], e["ts"]) for e in i] == [(2, 1.5), (1, 2_000_000.0)], i
    # A damaged recorder file and an empty request are refused, not guessed at.
    for bad in (lambda: export(recorders=[b"XXXX" + bytes(40)]), lambda: export()):
        try:
            bad()
        except ExportError:
            pass
        else:
            raise AssertionError("accepted what it should refuse")
    json.dumps(t)
    print("perfetto_export: self-test ok")


def main(argv):
    if argv[1:] == ["--self-test"]:
        self_test(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        return 0
    recorders, decisions, traces, out, hz = [], [], [], None, 10_000_000
    it = iter(argv[1:])
    try:
        for a in it:
            if a == "--recorder":
                recorders.append(open(next(it), "rb").read())
            elif a == "--decisions":
                p = next(it)
                decisions.append((p, open(p, "rb").read()))
            elif a == "--trace":
                traces.append(open(next(it), encoding="utf-8", errors="replace").read())
            elif a == "--hz":
                hz = int(next(it))
            elif a == "-o":
                out = next(it)
            else:
                raise ExportError(f"unknown argument {a}")
        if out is None:
            raise ExportError("-o out.json is required")
        doc = export(recorders, decisions, traces, hz)
    except (ExportError, StopIteration, OSError, ValueError) as e:
        print(f"perfetto_export: {e if str(e) else 'missing value'}", file=sys.stderr)
        print(__doc__.split("\n\n")[0], file=sys.stderr)
        return 2
    with open(out, "w") as f:
        json.dump(doc, f)
    n = sum(1 for e in doc["traceEvents"] if e["ph"] == "i")
    print(f"perfetto_export: {n} events -> {out} (open it at ui.perfetto.dev)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
