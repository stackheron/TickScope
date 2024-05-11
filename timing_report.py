#!/usr/bin/env python3
"""
Timing report: per task/ISR min/avg/max of CET, DT, RT, ST plus per-BSF-frame
CPU load, computed from a decoded scheduling trace (an InterpretedTraceData
CSV, or the rows produced in-memory by interpret) + a project file. No vendor host tool needed.

Metrics:

    CET  Core Execution Time  time actually on-CPU per job (preemption/wait excluded)
    DT   Delta Time           interval between consecutive Activations (observed period)
    RT   Response Time        Stop - Activation (release to termination)
    ST   Slack Time           Activation(next) - Stop(this)  (the gap; = period - RT)
    CPU load [%]              per BSF frame: 100 * (task CET in frame) / frame duration,
                             reported as min/avg/max over all frames (idle frames = 0%)

Event model (OSEK/AUTOSAR OS): one job is Activation -> Start -> [Wait -> Resume]* ->
Stop, where Wait = leaves RUNNING (preemption OR block, not distinguished) and Resume =
re-enters the SAME job -> a flat "one element runs at a time" timeline, not a stack.

BSF (Basic Scheduling Frame): one frame = the interval between two consecutive
occurrences of the BSF event, which the project file defines via <BasicSchedulingFrameEvent
SystemElementID=..> (e.g. the Activation of a 20 ms cyclic task). By
definition cpuLoad[%] = 100 * te/to with to = frame duration and te = sum
of CET in the frame; per task, te = that task's CET in the frame. Min/Avg/Max are taken
over the whole frame population, so frames in which a task never runs contribute 0 %
(pulling down its Min and Avg). Execution that straddles a frame boundary is split
between the two frames by time.

CET (and therefore the CPU load derived from it) carries the tracer's trace-overhead
compensation TickDuration*(2 + 4*nwait) per job (the job's own Start+Stop plus each
preemption's Wait+Resume+preemptor Start+Stop, one tick of trace-handler overhead each);
this reproduces the host CET exactly for ~3/4 of tasks and within a few us for the rest.
The compensation is distributed across a job's running segments in proportion to their
length. Pass compensate=False (--raw-cet) for the raw gross-of-overhead values. RT/ST/DT
are wall-clock, straight from the byte-exact event timestamps.
"""

import argparse
import bisect
import html as _htmlmod
import os
import re
import sys
from collections import defaultdict

_SKIP = {"InternalStart", "EndOfTrace", "SyncDataEvent", "Discontinuity"}


def fmt_ns(ns):
    """Duration format, e.g. '1ms 29us 120ns' / '156us 960ns' / '480ns'."""
    ns = int(round(ns))
    s, r = divmod(ns, 1_000_000_000)
    ms, r = divmod(r, 1_000_000)
    us, z = divmod(r, 1000)
    if s:
        return f"{s}s {ms}ms {us}us {z}ns"
    if ms:
        return f"{ms}ms {us}us {z}ns"
    if us:
        return f"{us}us {z}ns"
    return f"{z}ns"


def _pct(x, sep):
    if x is None:
        return "n/a"
    if x == 0:
        return f"0{sep}00"
    return f"{x:.4g}".replace(".", sep)


def pct_de(x):
    """Percentage, German decimal comma, ~4 significant figures ('13,42', '0,00'). CSV."""
    return _pct(x, ",")


def pct_dot(x):
    """Percentage, dot decimal (JS/parseFloat-friendly), ~4 sig figs ('13.42'). HTML."""
    return _pct(x, ".")


