#!/usr/bin/env python3
"""
Reproduce the reference "System report" per-CPU and per-process/thread BSF CPU
Load for a POSIX/QNX target, from an unattended trace stream captured in a
.pcapng/.pcap -- offline, no vendor host tool.

This is the POSIX/QNX sibling of timing_report.py (which handles the 32-bit MCU M7
format). The QNX target uses a DIFFERENT trace format, validated against a
real reference InterpretedTraceData.csv + System report:

  * 64-bit trace entries (2 uint32 LE words), datagram-aligned: each UDP datagram's
    trace payload (after the 4-byte [seq,..] sub-header) is a whole number of 8-byte
    entries. Pair PER DATAGRAM -- a global uint32 concat desyncs the pairing.
        entry = (hi<<32)|lo ; time24 = hi>>8 ; event8 = hi&0xFF ; traceInfo32 = lo
    24-bit clock (project MaxAbsTime=0xFFFFFF), tick from the project file (200 ns), wraps every
    ~3.35 s -- reconstruct time with modular deltas ((b-a)&0xFFFFFF), robust to the
    frequent wraps and to lossy-UDP dropped datagrams (per-datagram seq gaps).

  * Events (8-bit): 14 POSIX_SWITCH, 13 POSIX_WAIT, 17 POSIX_WAKEUP, 66 POSIX_PREEMPT,
    12 AP_GEN_ACTIVATE, 1/2 AP_GEN_START/STOP, 5/6 STOPWATCH, 30 TASK_NAME, 31 TASK_IDS,
    64/65/67/68 POSIX_CREATE/ADMIT/TERM/FREE, 69 TASK_MEM, 24 TRIGGER, 15 DISCONTINUITY.
    Continuation carriers = events 19..23 (folded into the preceding primary event).
    POSIX_SWITCH/WAIT/PREEMPT traceInfo = (CpuId<<24) | AppDefinedId(24-bit).

  * TASK_IDS(31) carriers define AppDefinedId -> (ProcessId, ThreadId, IsMainThread);
    TASK_NAME(30) carriers define AppDefinedId -> name. See fold code below.

  * Scheduling model (Model C, validated vs host per-CPU load within ~0.1-3.4 pp):
    POSIX_SWITCH(x) starts x running on its CpuId; POSIX_WAIT(x) stops x and the CPU
    goes idle until the next SWITCH; POSIX_PREEMPT(x) does NOT stop x (a preempted
    thread keeps the CPU until the replacing SWITCH); POSIX_WAKEUP only marks a thread
    ready. The QNX idle thread is a real per-CPU "Scheduler" process that switches in
    then immediately WAITs, so it naturally contributes ~0 load.

  * BSF (Basic Scheduling Frame): each AP_GEN_ACTIVATE(12) of the thread named by the
    project <POSIXBasicSchedulingFrameEvent SystemElementName=...> starts a new frame.
    Per-CPU (and per-thread) BSF CPU Load in a frame = on-CPU busy time in the frame /
    frame duration; execution straddling a boundary is split by time. Reported as
    min/avg/max over all frames.
"""

import argparse
import html
import struct
import sys
import bisect

TRACE_PLUGIN = 1
TRACE_STREAM_OP = 18
CARRIER = frozenset((19, 20, 21, 22, 23))
MASK24 = 0xFFFFFF
GAP = -1                 # sentinel event id for a dropped-datagram boundary
# scheduling events that carry (CpuId<<24)|AppId and partition CPU time
EV_SWITCH, EV_WAIT, EV_PREEMPT, EV_WAKEUP = 14, 13, 66, 17
EV_ACTIVATE = 12
EV_TASK_NAME, EV_TASK_IDS = 30, 31


# --------------------------------------------------------------------------- #
# project file parsing (POSIX system)
# --------------------------------------------------------------------------- #
def parse_project_posix(path):
    """Return dict with sid, name, tick, wrap, cpus, bsf_thread (name) for the
    POSIX system, plus {tid->sid} target map."""
    import re
    xml = open(path, encoding="utf-8-sig").read()
    spans = [(m.start(), m.group(0)) for m in re.finditer(r"<System\b[^>]*>", xml)]
    spans.append((len(xml), ""))
    tid2sid, posix = {}, None
    for i in range(len(spans) - 1):
        start, tag = spans[i]
        body = xml[start:spans[i + 1][0]]
        a = dict(re.findall(r'(\w+)="([^"]*)"', tag))
        sid = int(a.get("SID", "-1"))
        tm = re.search(r"<TargetId>(\d+)</TargetId>", body)
        if tm:
            tid2sid[int(tm.group(1))] = sid
        if "POSIX" in (a.get("SystemType", "") + a.get("Name", "")):
            bsf = re.search(r'<POSIXBasicSchedulingFrameEvent[^>]*SystemElementName="([^"]*)"', body)
            cpus = re.findall(r"<CpuId>(\d+)</CpuId>", body)
            posix = {
                "sid": sid,
                "name": a.get("Name", f"SID{sid}"),
                "tick": float(a.get("TickDuration", "0")),
                "wrap": int(a.get("MaxAbsTime", "16777215")) + 1,
                "cpus": [int(c) for c in cpus] or list(range(8)),
                "bsf_thread": bsf.group(1) if bsf else None,
                "bid": a.get("BID"),
            }
    return posix, tid2sid


# --------------------------------------------------------------------------- #
# stream extraction: 64-bit entries per datagram, with dropped-datagram markers
# --------------------------------------------------------------------------- #
