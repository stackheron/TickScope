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


