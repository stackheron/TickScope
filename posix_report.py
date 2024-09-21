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
def extract_posix(payloads, want_tid, flt=None):
    """Return (entries, endpoint) for the POSIX core. entries is a flat list of
    (time24, ev8, ti32); a (0, GAP, 0) sentinel marks a per-core seq discontinuity."""
    import stream_to_csv as tss
    flt = flt or {}
    entries, endpoint, seqprev = [], None, None
    for src, dst, sport, dport, buf, _ in payloads:
        if flt.get("src_ip") and src != flt["src_ip"]:
            continue
        if flt.get("dst_ip") and dst != flt["dst_ip"]:
            continue
        if flt.get("sport") is not None and sport != flt["sport"]:
            continue
        if flt.get("dport") is not None and dport != flt["dport"]:
            continue
        for tid, plugin, op, payload in tss.walk_frames(buf):
            if plugin != TRACE_PLUGIN or op != TRACE_STREAM_OP or len(payload) < 4:
                continue
            if tid != want_tid:
                continue
            if endpoint is None:
                endpoint = (src, dst, sport, dport)
            seq = payload[0]
            if seqprev is not None and (seqprev + 1) & 0xFF != seq:
                entries.append((0, GAP, 0))
            seqprev = seq
            body = payload[4:]
            n = len(body) // 8
            if n == 0:
                continue
            words = struct.unpack(f"<{2 * n}I", body[:8 * n])
            for e in range(n):
                lo, hi = words[2 * e], words[2 * e + 1]
                entries.append(((hi >> 8) & MASK24, hi & 0xFF, lo))
    return entries, endpoint


# --------------------------------------------------------------------------- #
# fold TASK_IDS / TASK_NAME -> App-Defined-Id registry
# --------------------------------------------------------------------------- #
def build_registry(entries):
    """Return {appid: {'pid','tid','main','name'}} from TASK_IDS(31)/TASK_NAME(30)."""
    N = len(entries)
    reg = {}

    def carriers(k):
        c, j = [], k + 1
        while j < N and entries[j][1] in CARRIER:
            c.append(entries[j])
            j += 1
        return c, j

    k = 0
    while k < N:
        _, ev, _ = entries[k]
        if ev == EV_TASK_IDS:
            c, k = carriers(k)
            if len(c) >= 2:
                appid = c[0][0]
                pid = c[0][2] >> 8
                tid = c[1][0] >> 8
                main = bool((c[1][2] >> 16) & 1)
                d = reg.setdefault(appid, {})
                d.update(pid=pid, tid=tid, main=main)
            continue
        if ev == EV_TASK_NAME:
            c, k = carriers(k)
            if c:
                appid = c[0][0]                 # first carrier hi[1:4] = appid
                name = _name_from_carriers(c)
                if name:
                    reg.setdefault(appid, {})["name"] = name
            continue
        k += 1
    return reg


def _name_from_carriers(c):
    """Reconstruct a TASK_NAME string (byte order validated on QNX):
      - first carrier (ev20): name bytes = lo[1:4] (lo[0] is a 0 marker; hi = appid)
      - each full ev20 carrier: name bytes = hi[1:4] then lo[0:4]  (7 bytes)
      - the ev21 terminator: trailing name bytes = lo[0:4] only (hi is a timestamp)
    NUL-terminated."""
    def lo_bytes(e):
        return struct.pack("<I", e[2])                # 4 bytes of the lo word
    def hi_bytes(e):
        return struct.pack("<I", (e[0] << 8) | e[1])  # rebuild hi = (time24<<8)|ev

    nb = bytearray(lo_bytes(c[0])[1:4])
    for cc in c[1:]:
        if cc[1] == 20:                               # full data carrier
            nb += hi_bytes(cc)[1:4]
            nb += lo_bytes(cc)[0:4]
        else:                                         # ev21 terminator: lo tail only
            nb += lo_bytes(cc)[0:4]
            break
    return nb.split(b"\x00")[0].decode("latin1", "replace").strip()


# --------------------------------------------------------------------------- #
# scheduling model (Model C) -> per-CPU / per-thread busy intervals + BSF frames
# --------------------------------------------------------------------------- #
