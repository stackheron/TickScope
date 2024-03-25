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


def interpret(entries, sysinfo, buf_base=None, start_pos=0, gap_hints=None):
    """entries must be in chronological order. Returns list of column dicts.

    gap_hints (optional, stream captures): {entry_index: (q, elapsed_ns)} at each
    dropped-datagram gap, used to recover timestamp wraps lost in the gap."""
    if not entries:
        raise ValueError("no trace entries")
    gap_hints = gap_hints or {}
    tick, wrap = sysinfo["tick"], sysinfo["wrap"]
    tasks = sysinfo["by_type"].get("Task", {})
    name = sysinfo["name"]
    sid = sysinfo.get("sid", "")
    n = len(entries)
    rows = []
    prev_ts = None
    abs_ticks = 0
    base = None
    last_time = 0

    def blank():
        return {c: "" for c in COLS}

    # synthetic InternalStart: state at trace start = first entry's element
    first = entries[0]
    r = blank()
    r.update({"Index": 0, "Time (Ns)": 0, "Time": "0ns", "Event Type": "InternalStart",
              "Element Name": tasks.get(first & 0x3FF, ""), "System": name,
              "Ref. Raw Index": 1, "System Id": sid, "Task Id": first & 0x3FF})
    rows.append(r)

    i = 0
    while i < n:
        e = entries[i]
        ts, ev, info = (e >> 16) & 0xFFFF, (e >> 10) & 0x3F, e & 0x3FF
        raw_index = i + 1
        if ev == 15:
            time_ns = last_time
        else:
            if prev_ts is None:
                abs_ticks = ts
            else:
                delta = (ts - prev_ts) % wrap
                if i in gap_hints:
                    delta += wrap * _gap_wraps(entries, i, gap_hints[i], delta, tick, wrap)
                abs_ticks += delta
            if base is None:
                base = abs_ticks
            time_ns = int(round((abs_ticks - base) * tick))
            prev_ts, last_time = ts, time_ns
        raw_evt, evt = EVENTS.get(ev, (f"EVENT_{ev}", f"Event{ev}"))

        r = blank()
        r.update({"Index": len(rows), "Time (Ns)": time_ns, "Time": fmt_time(time_ns),
                  "Event Type": evt, "Trace Info": f"0x{info:03X}", "System": name,
                  "Raw Index": raw_index, "Raw Trace Entry": f"0x{e:08X}",
                  "Raw Time": ts, "Raw Event Type": raw_evt, "Event Id": ev,
                  "System Id": sid})
        if buf_base is not None:
            r["Trace Buffer Address"] = f"0x{buf_base + ((start_pos + i) % n) * 4:08X}"
        if ev in SCHED_EVENTS:
            r["Element Name"] = tasks.get(info, "")
            r["Task Id"] = info
        elif ev == 15:
            r["Discontinuity Type"] = "Tracing halted"
        elif ev == 18:
            # fold sync-data continuations into a 32-bit sync timer value:
            # low 16 bits = this ts, next carriers supply the upper bytes.
            sync = ts
            shift = 16
            j = i + 1
            while j < n and ((entries[j] >> 10) & 0x3F) in SYNC_CONT:
                sync |= (entries[j] & 0xFF) << shift
                shift += 8
                j += 1
            r["Sync Data Time"] = sync & 0xFFFFFFFF
            i = j - 1  # consume the folded carriers
        rows.append(r)
        i += 1

    r = blank()
    r.update({"Index": len(rows), "Time (Ns)": last_time, "Time": fmt_time(last_time),
              "Event Type": "EndOfTrace", "System": name, "System Id": sid})
    rows.append(r)
    return rows


