#!/usr/bin/env python3
"""
Interpret a raw trace block (uint32 LE, e.g. from stream_to_csv.py
--bin-out, or an exported RawTraceData.csv) into
InterpretedTraceData, using a project file for element
names and timing.

Trace buffer = array of uint32 trace-entry records:

    entry = (rawTime << 16) | (eventId << 10) | traceInfo
        bits[31:16]  rawTime    16-bit rolling timestamp (wraps at MaxAbsTime+1)
        bits[15:10]  eventId     event type (see EVENTS below)
        bits[9:0]    traceInfo   element id (Task/ISR/thread) for scheduling events,
                                 or control payload for trigger/sync/discontinuity

The read-out is in ring/address order; the DISCONTINUITY marker sits at the write
pointer (newest entry), so rotating the buffer to put it last reconstructs the
chronological order (matching what the host tool does with the write pointer).

Absolute time (ns) = unwrapped rawTime * TickDuration (from the project file). Element names
come from the project file <SystemElement ID Name Type="Task"> table for the matching System.

Validated byte-for-byte against a reference InterpretedTraceData.csv export (Time,
Event Type, Trace Info, Element Name all match for every entry).
"""

import argparse
import re
import struct
import sys

# event id -> (RawEventType, EventType)  (names match the InterpretedTraceData columns)
EVENTS = {
    1:  ("START",          "Start"),
    2:  ("STOP",           "Stop"),
    12: ("ACTIVATION",     "Activation"),
    13: ("WAIT",           "Wait"),
    14: ("RESUME",         "Resume"),
    15: ("DISCONTINUITY",  "Discontinuity"),
    18: ("SYNCDATA_START", "SyncDataEvent"),
    24: ("TRIGGER",        "Trigger"),
}
SCHED_EVENTS = {1, 2, 12, 13, 14}       # traceInfo is a Task element id
SYNC_CONT = {19, 20, 21, 22, 23}        # sync-data continuation carriers (folded)

# full InterpretedTraceData column order
COLS = ["Index", "Time (Ns)", "Time", "Event Type", "Trace Info", "Element Name",
        "System", "Raw Index", "Ref. Raw Index", "Trace Buffer Address",
        "Raw Trace Entry", "Raw Time", "Raw Event Type", "Event Id", "System Id",
        "Cross Core Id Offset", "Discontinuity Type", "Cpu Id", "Process Id",
        "Thread Id", "Is Main Thread", "App Defined Id", "Task Id",
        "Task Name Payload", "Runnable Id", "Stopwatch Id", "User Event Id",
        "User Event Payload", "User Data Type", "Sync Data Time", "Timestamp",
        "Memory Information Event Payload", "Errors And Information"]


def parse_project(path):
    """Return {sid: {'name','tick','wrap','by_type':{Type:{id:name}}}}."""
    xml = open(path, encoding="utf-8-sig").read()
    spans = [(m.start(), m.group(0)) for m in re.finditer(r"<System\b[^>]*>", xml)]
    spans.append((len(xml), ""))
    systems = {}
    for i in range(len(spans) - 1):
        start, tag = spans[i]
        body = xml[start:spans[i + 1][0]]
        a = dict(re.findall(r'(\w+)="([^"]*)"', tag))
        sid = int(a.get("SID", "-1"))
        by_type = {}
        for em in re.finditer(r"<SystemElement\b[^>]*>", body):
            ea = dict(re.findall(r'(\w+)="([^"]*)"', em.group(0)))
            if "ID" in ea and "Name" in ea:
                by_type.setdefault(ea.get("Type", "Task"), {})[int(ea["ID"])] = ea["Name"]
        systems[sid] = {"name": a.get("Name", f"SID{sid}"),
                        "tick": float(a.get("TickDuration", "0")),
                        "wrap": int(a.get("MaxAbsTime", "65535")) + 1,
                        "by_type": by_type}
    return systems


def read_entries_bin(path):
    data = open(path, "rb").read()
    n = len(data) // 4
    return list(struct.unpack(f"<{n}I", data[: n * 4]))


def read_entries_rawcsv(path):
    entries = []
    with open(path, encoding="utf-8-sig") as f:
        col = f.readline().rstrip("\n").split(";").index("Raw Trace Entry")
        for line in f:
            p = line.rstrip("\n").split(";")
            if len(p) > col and p[col]:
                entries.append(int(p[col], 16))
    return entries


def reorder_ring(entries):
    """Rotate a ring-order buffer so the DISCONTINUITY marker (write pointer) is
    last -> chronological order. Returns entries unchanged if no discontinuity."""
    disc = [i for i, e in enumerate(entries) if ((e >> 10) & 0x3F) == 15]
    if not disc:
        return entries, False
    start = (disc[-1] + 1) % len(entries)
    return entries[start:] + entries[:start], True


def fmt_time(ns):
    s, rem = divmod(ns, 1_000_000_000)
    ms, rem = divmod(rem, 1_000_000)
    us, z = divmod(rem, 1000)
    if s:
        return f"{s}s {ms:03d}ms {us:03d}us {z:03d}ns"
    if ms:
        return f"{ms}ms {us:03d}us {z:03d}ns"
    if us:
        return f"{us}us {z:03d}ns"
    return f"{z}ns"


def _gap_wraps(entries, i, hint, delta, tick, wrap):
    """Timestamp wraps lost in a dropped-datagram gap before entries[i].

    hint = (q, elapsed_ns): q indexes the last entry of the frame that starts at i
    and elapsed_ns is the capture-clock time between the last entry before the gap and
    entries[q]. The trace itself covers delta (gap edge) + span (i..q) ticks of that;
    whatever remains, rounded to whole wrap periods, was lost in the gap."""
    q, elapsed_ns = hint
    if tick <= 0:
        return 0
    span = 0
    prev = (entries[i] >> 16) & 0xFFFF
    for e in entries[i + 1:q + 1]:
        ev = (e >> 10) & 0x3F
        if ev == 15 or ev in SYNC_CONT:
            continue
        ts = (e >> 16) & 0xFFFF
        span += (ts - prev) % wrap
        prev = ts
    return max(0, round((elapsed_ns / tick - delta - span) / wrap))


