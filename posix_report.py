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
def build_intervals(entries, reg, tick):
    """Walk the trace once. Return acts, cpu_runs, thr_runs, gaps, (t_first,t_last).
      acts     : {appid: [activation absolute-ns...]} from AP_GEN_ACTIVATE (BSF source)
      cpu_runs : (start,end,cpu,appid) for PER-CPU load -- a preempted thread keeps the
                 CPU busy until the replacing SWITCH (Model C: PREEMPT does not idle it)
      thr_runs : (start,end,cpu,appid) for PER-THREAD CET -- PREEMPT ends the thread's
                 run (the preempt->switch scheduling-latency gap is credited to no thread)
    Absolute ns uses modular 24-bit deltas; at a GAP/DISCONTINUITY (lossy-UDP boundary)
    in-flight runs are dropped and the spanning frame excluded (time is not comparable)."""
    acts, cpu_runs, thr_runs, gaps = {}, [], [], []
    cur = {}          # cpu -> [start_ns, appid, thr_open]  (thr_open False after PREEMPT)
    now = None
    lastraw = None
    t_first = t_last = None
    for t, ev, ti in entries:
        if ev == GAP or ev == 15:
            cur = {}
            if now is not None:
                gaps.append(now)
            continue
        if ev in CARRIER:
            continue
        if now is None:
            now = t_first = 0
        else:
            now += ((t - lastraw) & MASK24) * tick   # ticks -> ns (modular, wrap-safe)
        lastraw = t
        t_last = now

        if ev == EV_ACTIVATE:
            acts.setdefault(ti & MASK24, []).append(now)
            continue
        if ev in (EV_SWITCH, EV_WAIT, EV_PREEMPT):
            cpu = (ti >> 24) & 0xFF
            app = ti & MASK24
            if cpu > 63:
                continue
            c = cur.get(cpu)
            if ev == EV_SWITCH:
                if c is not None:               # close previous owner
                    cpu_runs.append((c[0], now, cpu, c[1]))
                    if c[2]:
                        thr_runs.append((c[0], now, cpu, c[1]))
                cur[cpu] = [now, app, True]
            elif ev == EV_WAIT:                 # owner blocks; CPU idle until next SWITCH
                if c is not None:
                    cpu_runs.append((c[0], now, cpu, c[1]))
                    if c[2]:
                        thr_runs.append((c[0], now, cpu, c[1]))
                    del cur[cpu]
            elif ev == EV_PREEMPT:              # thread stops, CPU stays owned till SWITCH
                if c is not None and c[2]:
                    thr_runs.append((c[0], now, cpu, c[1]))
                    c[2] = False
    return acts, cpu_runs, thr_runs, sorted(gaps), (t_first, t_last)


def _frame_loads(runs, frames, keyfn):
    """Per-frame busy fraction (%) per key. keyfn(cpu, appid) -> hashable key (or None
    to skip). Returns {key: [load_per_frame...]} covering every frame (0 where idle)."""
    nf = len(frames) - 1
    if nf <= 0:
        return {}, nf
    fdur = [frames[i + 1] - frames[i] for i in range(nf)]
    busy = {}                                   # key -> [ns per frame]
    for s, e, cpu, app in runs:
        if e <= s:
            continue
        key = keyfn(cpu, app)
        if key is None:
            continue
        arr = busy.get(key)
        if arr is None:
            arr = busy[key] = [0.0] * nf
        i = bisect.bisect_right(frames, s) - 1
        while 0 <= i < nf and frames[i] < e:
            lo = s if s > frames[i] else frames[i]
            hi = e if e < frames[i + 1] else frames[i + 1]
            if hi > lo:
                arr[i] += hi - lo
            i += 1
    loads = {k: [100.0 * arr[i] / fdur[i] if fdur[i] else 0.0 for i in range(nf)]
             for k, arr in busy.items()}
    return loads, nf


def _stats(vals):
    n = len(vals)
    if n == 0:
        return 0.0, 0.0, 0.0, 0
    return min(vals), sum(vals) / n, max(vals), n


# --------------------------------------------------------------------------- #
# report orchestration
# --------------------------------------------------------------------------- #
def compute_report(entries, sysinfo, reg, bsf_appid=None, frame_ms=20.0):
    """Return (cpu_stats, proc_rows, nframes, mode). cpu_stats: {cpu:(min,avg,max,n)}.
    proc_rows: per-process rows with threads + per-CPU breakdown (empty if no config).
    mode: 'bsf' (framed by the reference thread), 'appid' (by --bsf-appid), or
    'synthetic' (config-less capture -> fixed-width windows; avg is meaningful, min/max
    reflect the window grid; per-process/thread unavailable without TASK_IDS/TASK_NAME)."""
    acts, cpu_runs, thr_runs, gaps, (t_start, t_end) = build_intervals(entries, reg, sysinfo["tick"])

    # choose BSF frame boundaries
    bsf_name = sysinfo.get("bsf_thread")
    bsf_appids = {a for a, d in reg.items() if d.get("name") == bsf_name}
    if bsf_appid is not None and bsf_appid in acts:
        frames, mode = sorted(acts[bsf_appid]), "appid"
    elif bsf_appids:
        frames, mode = sorted(t for a in bsf_appids for t in acts.get(a, [])), "bsf"
    elif t_start is not None and t_end > t_start:
        # config-less capture: no named BSF thread -> uniform synthetic windows
        w = max(int(frame_ms * 1e6), 1)
        frames = list(range(int(t_start), int(t_end) + w, w))
        mode = "synthetic"
    else:
        frames = []
        mode = "synthetic"

    # exclude BSF frames that span a lossy gap / discontinuity (the host does too --
    # its report warns "system contains discontinuity"); such frames have missing
    # spans that would otherwise read as artificial 0% (min) or >100% (max) spikes.
    nf = max(len(frames) - 1, 0)
    valid = [True] * nf
    for g in gaps:
        i = bisect.bisect_right(frames, g) - 1
        # the gap frame AND the next frame are distorted: at a lossy boundary the
        # modular time reconstruction can't recover the elapsed span, so the frame
        # holding the gap (missing spans) and the one after it (skewed duration/base)
        # are both dropped -- matching how the host flags discontinuity frames.
        for j in (i, i + 1):
            if 0 <= j < nf:
                valid[j] = False

    def st(vals):
        return _stats([v for v, ok in zip(vals, valid) if ok])

    cpus = sysinfo["cpus"]
    ncpu = len(cpus) or 1
    cpu_loads, _ = _frame_loads(cpu_runs, frames, lambda cpu, app: cpu if cpu in cpus else None)
    cpu_stats = {c: st(cpu_loads.get(c, [0.0] * nf)) for c in cpus}

    # per (pid,tid): total load + per-CPU breakdown (thread CET: PREEMPT ends the run)
    thr_tot, _ = _frame_loads(thr_runs, frames,
                              lambda cpu, app: (reg.get(app, {}).get("pid"),
                                                reg.get(app, {}).get("tid")))
    thr_cpu, _ = _frame_loads(thr_runs, frames,
                              lambda cpu, app: ((reg.get(app, {}).get("pid"),
                                                 reg.get(app, {}).get("tid"), cpu)
                                                if cpu in cpus else None))
    # group threads under processes
    procs = {}
    for (pid, tid), vals in thr_tot.items():
        if pid is None:
            continue
        # process name = its main thread's name (QNX names the main thread after the
        # process image), falling back to any named thread of the process
        name = next((d.get("name") for a, d in reg.items()
                     if d.get("pid") == pid and d.get("main") and d.get("name")), None) \
            or next((d.get("name") for a, d in reg.items()
                     if d.get("pid") == pid and d.get("name")), None)
        p = procs.setdefault(pid, {"pid": pid, "name": name or "?", "threads": [],
                                   "frames": [0.0] * nf})
        # total "BSF CPU Load" is normalised by total multi-core capacity (/ ncpu);
        # per-CPU columns stay relative to a single CPU.
        tvals = [v / ncpu for v in vals]
        for i in range(nf):
            p["frames"][i] += tvals[i]
        tname = next((d.get("name") for a, d in reg.items()
                      if d.get("pid") == pid and d.get("tid") == tid and d.get("name")),
                     None)
        percpu = {c: st(thr_cpu.get((pid, tid, c), [0.0] * nf)) for c in cpus}
        p["threads"].append({"tid": tid, "name": tname or "", "stats": st(tvals),
                             "percpu": percpu})

    proc_rows = []
    for pid, p in procs.items():
        p["stats"] = st(p["frames"])
        p["threads"].sort(key=lambda t: -t["stats"][1])
        proc_rows.append(p)
    proc_rows.sort(key=lambda p: -p["stats"][1])
    return cpu_stats, proc_rows, sum(valid), mode


