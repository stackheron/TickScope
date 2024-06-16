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


def parse_project_elements(path):
    """Return {sid: {name: {'id','prio','type'}}} for every <System>."""
    xml = open(path, encoding="utf-8-sig").read()
    starts = [m.start() for m in re.finditer(r"<System\b", xml)] + [len(xml)]
    systems = {}
    for i in range(len(starts) - 1):
        body = xml[starts[i]:starts[i + 1]]
        tag = re.match(r"<System\b[^>]*>", body)
        sid = int(dict(re.findall(r'(\w+)="([^"]*)"', tag.group(0))).get("SID", "-1")) if tag else -1
        elems = {}
        for m in re.finditer(r"<SystemElement\b[^>]*>", body):
            a = dict(re.findall(r'(\w+)="([^"]*)"', m.group(0)))
            if a.get("Type") == "Task" and "Name" in a:
                elems[a["Name"]] = {"id": a.get("ID", ""), "prio": a.get("Priority", ""),
                                    "type": a.get("Type", "Task")}
        systems[sid] = elems
    return systems


def parse_bsf_task(path, sid):
    """Return the name of the task whose activation defines the BSF frame, or None."""
    xml = open(path, encoding="utf-8-sig").read()
    starts = [m.start() for m in re.finditer(r"<System\b", xml)] + [len(xml)]
    for i in range(len(starts) - 1):
        body = xml[starts[i]:starts[i + 1]]
        tag = re.match(r"<System\b[^>]*>", body)
        s = int(dict(re.findall(r'(\w+)="([^"]*)"', tag.group(0))).get("SID", "-1")) if tag else -1
        if s != sid:
            continue
        m = re.search(r"<BasicSchedulingFrameEvent[^>]*SystemElementID=\"(\d+)\"", body)
        if not m:
            return None
        bid = m.group(1)
        for em in re.finditer(r"<SystemElement\b[^>]*>", body):
            a = dict(re.findall(r'(\w+)="([^"]*)"', em.group(0)))
            if a.get("Type") == "Task" and a.get("ID") == bid:
                return a.get("Name")
    return None


def _tick_from_project(path, sid):
    xml = open(path, encoding="utf-8-sig").read()
    for m in re.finditer(r"<System\b[^>]*>", xml):
        a = dict(re.findall(r'(\w+)="([^"]*)"', m.group(0)))
        if int(a.get("SID", "-1")) == sid:
            return float(a.get("TickDuration", "0"))
    return 0.0


def _bid_from_project(path, sid):
    """Return the <System> BID (decimal string) for sid, or None."""
    xml = open(path, encoding="utf-8-sig").read()
    for m in re.finditer(r"<System\b[^>]*>", xml):
        a = dict(re.findall(r'(\w+)="([^"]*)"', m.group(0)))
        if int(a.get("SID", "-1")) == sid and a.get("BID"):
            return a["BID"]
    return None


def _decode_bid(bid):
    """Format a build id (project <System BID>) as 'NNN (0xHEX)'."""
    try:
        v = int(bid)
    except (TypeError, ValueError):
        return None
    return f"{v} (0x{v:08X})"


def events_from_interp_csv(path):
    """Return (events, sid, sysname, captured); events = [(time_ns, event, element)].

    captured = the first non-empty 'Timestamp' (wall-clock) cell if the CSV carries one
    (host-generated traces annotate sync rows with it), else '' ."""
    events, sid, sysname, captured = [], None, "", ""
    with open(path, encoding="utf-8-sig") as f:
        h = f.readline().rstrip("\r\n").split(";")
        ti, ei, eli = h.index("Time (Ns)"), h.index("Event Type"), h.index("Element Name")
        sii = h.index("System Id") if "System Id" in h else None
        syi = h.index("System") if "System" in h else None
        tsi = h.index("Timestamp") if "Timestamp" in h else None
        for line in f:
            p = line.rstrip("\r\n").split(";")
            if len(p) <= eli:
                continue
            events.append((int(p[ti]) if p[ti] else 0, p[ei], p[eli]))
            if sid is None and sii is not None and p[sii]:
                sid = int(p[sii])
            if not sysname and syi is not None and p[syi]:
                sysname = p[syi]
            if not captured and tsi is not None and len(p) > tsi and p[tsi]:
                captured = p[tsi]
    return events, sid, sysname, captured


def _fmt_dur(ns):
    """Human trace duration, e.g. '5.9035 s' / '842.10 ms'."""
    if ns >= 1_000_000_000:
        return f"{ns / 1e9:.4f} s"
    if ns >= 1_000_000:
        return f"{ns / 1e6:.2f} ms"
    return f"{ns / 1e3:.1f} us"


def _build_meta(source, project, events, captured, sid=None):
    ts = [e[0] for e in events]
    dur = (max(ts) - min(ts)) if ts else 0
    bid = _decode_bid(_bid_from_project(project, sid)) if (project and sid is not None) else None
    return {"source": os.path.basename(source) if source else "",
            "project": os.path.basename(project) if project else "",
            "duration": dur, "captured": captured or "",
            "bid": bid or ""}


def events_from_interp_rows(rows):
    """Adapt interpret.interpret() output dicts -> (time, event, element) tuples."""
    return [(int(r["Time (Ns)"]) if r["Time (Ns)"] != "" else 0,
             r["Event Type"], r["Element Name"]) for r in rows]


def compute_stats(events, tick, compensate=True):
    """Return (stats, intervals).

    stats[element] = {'count','cet','dt','rt','st','acts'} (lists of ns).
    intervals = [(start, end, element, scale)] running segments; scale distributes each
    job's CET overhead compensation across its segments (scale=1 when compensate=False).
    """
    cet_out = defaultdict(list)
    rt = defaultdict(list)
    acts = defaultdict(list)
    jobseq = defaultdict(list)          # (act_t, stop_t) per job
    intervals = []
    openj = {}
    pending_act = {}
    running = [None]
    last_t = [events[0][0] if events else 0]

    def charge(t):
        d = t - last_t[0]
        if running[0] is not None and d and running[0] in openj:
            openj[running[0]]["cet"] += d
        last_t[0] = t

    for t, ev, el in events:
        if ev in _SKIP:
            charge(t)
            continue
        charge(t)
        if ev == "Activation":
            acts[el].append(t)
            pending_act[el] = t
        elif ev == "Start":
            openj[el] = {"cet": 0, "nwait": 0, "act": pending_act.pop(el, None),
                         "segs": [], "seg": t}
            running[0] = el
        elif ev == "Resume":
            j = openj.get(el)
            if j is None:
                openj[el] = {"cet": 0, "nwait": 0, "act": None, "segs": [], "seg": t}
            else:
                j["seg"] = t
            running[0] = el
        elif ev == "Wait":
            if running[0] == el:
                running[0] = None
            j = openj.get(el)
            if j is not None:
                j["nwait"] += 1
                if j["seg"] is not None:
                    j["segs"].append((j["seg"], t))
                    j["seg"] = None
        elif ev == "Stop":
            if running[0] == el:
                running[0] = None
            j = openj.pop(el, None)
            if j is not None:
                if j["seg"] is not None:
                    j["segs"].append((j["seg"], t))
                cet = j["cet"]
                comp = tick * (2 + 4 * j["nwait"]) if compensate else 0
                eff = max(0, cet - comp)
                scale = (eff / cet) if cet > 0 else 0.0
                cet_out[el].append(eff)
                for s, e in j["segs"]:
                    intervals.append((s, e, el, scale))
                if j["act"] is not None:
                    rt[el].append(t - j["act"])
                jobseq[el].append((j["act"], t))

    dt = {el: [a[i] - a[i - 1] for i in range(1, len(a))] for el, a in acts.items()}
    st = defaultdict(list)
    for el, js in jobseq.items():
        for i in range(1, len(js)):
            if js[i][0] is not None:
                st[el].append(js[i][0] - js[i - 1][1])

    stats = {}
    for el in set(cet_out) | set(acts):
        stats[el] = {"count": len(cet_out.get(el, [])), "cet": cet_out.get(el, []),
                     "dt": dt.get(el, []), "rt": rt.get(el, []), "st": st.get(el, []),
                     "acts": acts.get(el, [])}
    return stats, intervals


def bsf_frames(stats, bsf_name):
    """Frames = consecutive activations of the BSF task -> [(start, end)]."""
    a = stats.get(bsf_name, {}).get("acts", [])
    return [(a[i], a[i + 1]) for i in range(len(a) - 1)]


def bsf_loads(intervals, frames):
    """Return ({element: [load% per frame]}, [system load% per frame])."""
    if not frames:
        return {}, []
    fstart = [a for a, _ in frames]
    per = defaultdict(lambda: defaultdict(float))
    sysf = defaultdict(float)
    for a, b, el, scale in intervals:
        if b <= a or scale <= 0:
            continue
        fi = bisect.bisect_right(fstart, a) - 1
        if fi < 0:
            fi = 0
        while fi < len(frames) and frames[fi][0] < b:
            fa, fb = frames[fi]
            ov = min(b, fb) - max(a, fa)
            if ov > 0:
                per[el][fi] += ov * scale
                sysf[fi] += ov * scale
            fi += 1
    durs = [fb - fa for fa, fb in frames]
    loads = {}
    for el, fm in per.items():
        loads[el] = [100.0 * fm.get(i, 0.0) / durs[i] if durs[i] else 0.0
                     for i in range(len(frames))]
    sysload = [100.0 * sysf.get(i, 0.0) / durs[i] if durs[i] else 0.0
               for i in range(len(frames))]
    return loads, sysload


def _order_by_prio(stats, elems):
    """Sort elements by priority (highest first); busiest-first within equal priority."""
    def key(el):
        p = str(elems.get(el, {}).get("prio", ""))
        pr = int(p) if p.lstrip("-").isdigit() else -1
        return (-pr, -sum(stats[el]["cet"]))
    return sorted(stats, key=key)


_COLS = ["Name", "Type", "ID", "Priority", "Count",
         "CET Min", "CET Avg", "CET Max", "DT Min", "DT Avg", "DT Max",
         "RT Min", "RT Avg", "RT Max", "ST Min", "ST Avg", "ST Max",
         "CPU Load Min [%]", "CPU Load Avg [%]", "CPU Load Max [%]"]


def _mmm_t(vals):
    if not vals:
        return ["n/a", "n/a", "n/a"]
    return [fmt_ns(min(vals)), fmt_ns(sum(vals) / len(vals)), fmt_ns(max(vals))]


def _mmm_pct(vals):
    if not vals:
        return ["n/a", "n/a", "n/a"]
    return [pct_de(min(vals)), pct_de(sum(vals) / len(vals)), pct_de(max(vals))]


def write_report(stats, intervals, elems, bsf_name, sysname, path, meta=None):
    """Write the per-element CET/DT/RT/ST + BSF CPU-load table (priority-sorted)."""
    meta = meta or {}
    frames = bsf_frames(stats, bsf_name)
    loads, sysload = bsf_loads(intervals, frames)
    order = _order_by_prio(stats, elems)
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        f.write(f"System;{sysname}\n")
        if meta.get("source"):
            f.write(f"Source;{meta['source']}\n")
        if meta.get("project"):
            f.write(f"Project;{meta['project']}\n")
        if meta.get("bid"):
            f.write(f"Expected BID;{meta['bid']}\n")
        if meta.get("duration"):
            f.write(f"Trace duration;{_fmt_dur(meta['duration'])}\n")
        if meta.get("captured"):
            f.write(f"Captured;{meta['captured']}\n")
        if frames:
            avg_ms = sum(fb - fa for fa, fb in frames) / len(frames) / 1e6
            f.write(f"BSF event;{bsf_name or '?'};frames;{len(frames)};avg period;{avg_ms:.3f}ms\n")
            if sysload:
                f.write(f"BSF CPU load min [%];{pct_de(min(sysload))};"
                        f"average [%];{pct_de(sum(sysload)/len(sysload))};"
                        f"max [%];{pct_de(max(sysload))}\n")
        else:
            f.write("BSF event;(none - no CPU load computed)\n")
        f.write(";".join(_COLS) + "\n")
        for el in order:
            s = stats[el]
            emeta = elems.get(el, {"id": "", "prio": "", "type": "Task"})
            name = f"{el} ID:{emeta['id']} prio:{emeta['prio']}" if emeta["id"] != "" else el
            row = [name, emeta.get("type", "Task"), emeta["id"], emeta["prio"], s["count"]]
            row += _mmm_t(s["cet"]) + _mmm_t(s["dt"]) + _mmm_t(s["rt"]) + _mmm_t(s["st"])
            row += _mmm_pct(loads.get(el)) if frames else ["n/a", "n/a", "n/a"]
            f.write(";".join(str(x) for x in row) + "\n")
    return len(order)


_HTML_CSS = r"""
:root{--bg:#fff;--fg:#1b1f24;--muted:#6b7280;--line:#e5e7eb;--head:#f7f8fa;
  --zebra:#fafbfc;--accent:#2563eb;--bar:#dbeafe;--grp:#cbd5e1;--chip:#f1f5f9;}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--fg:#e6e8eb;--muted:#9aa4b2;
  --line:#262b34;--head:#171b22;--zebra:#141821;--accent:#60a5fa;--bar:#1d3350;
  --grp:#3a424f;--chip:#1a1f28;}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
  font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;}
.wrap{padding:24px;max-width:100%;}
h1{font-size:19px;margin:0 0 2px;font-weight:650;}
.sub{color:var(--muted);font-size:13px;margin-bottom:12px;}
.meta{border-collapse:collapse;margin:0 0 18px;font-size:12.5px;}
.meta td{border-bottom:none;padding:2px 18px 2px 0;white-space:nowrap;vertical-align:top;}
.meta td.k{color:var(--muted);text-transform:uppercase;font-size:10.5px;letter-spacing:.04em;}
.meta td.v{color:var(--fg);font-weight:600;word-break:break-word;}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:18px;}
.card{border:1px solid var(--line);border-radius:8px;padding:9px 13px;min-width:110px;background:var(--chip);}
.card .k{color:var(--muted);font-size:10.5px;text-transform:uppercase;letter-spacing:.04em;}
.card .v{font-size:17px;font-weight:640;margin-top:3px;font-variant-numeric:tabular-nums;}
.tablewrap{overflow-x:auto;border:1px solid var(--line);border-radius:8px;}
table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums;}
th,td{padding:6px 10px;border-bottom:1px solid var(--line);white-space:nowrap;}
thead th{position:sticky;top:0;background:var(--head);z-index:2;font-size:12px;font-weight:600;}
thead tr:first-child th{border-bottom:1px solid var(--line);}
th.sortable{cursor:pointer;user-select:none;}
th.sortable:hover{color:var(--accent);}
th.sortable:hover::after{content:"\2195";margin-left:4px;font-size:9px;opacity:.5;}
th.sortable.asc::after{content:"\25B2";margin-left:4px;font-size:9px;opacity:1;}
th.sortable.desc::after{content:"\25BC";margin-left:4px;font-size:9px;opacity:1;}
th.grp{text-align:center;color:var(--muted);text-transform:uppercase;letter-spacing:.03em;font-size:11px;}
.gl{border-left:2px solid var(--grp);}
td.num,th.num{text-align:right;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;}
td.name{text-align:left;font-weight:550;}
tbody tr:nth-child(even){background:var(--zebra);}
tbody tr:hover{background:var(--chip);}
.muted{color:var(--muted);}
.bar{position:relative;overflow:hidden;}
.bar>i{position:absolute;left:0;top:0;bottom:0;background:var(--bar);z-index:0;}
.bar>b{position:relative;z-index:1;font-weight:500;}
footer{color:var(--muted);font-size:12px;margin-top:16px;line-height:1.6;}
footer code{background:var(--chip);padding:1px 5px;border-radius:4px;}
"""

_HTML_JS = r"""<script>
(function(){
  var t=document.getElementById('report'); if(!t) return;
  var tb=t.tBodies[0], hs=t.querySelectorAll('th.sortable'), cc=-1, cd=1;
  function val(tr,c,s){
    var td=tr.children[c];
    if(td.dataset.sort!==undefined && td.dataset.sort!=='') return parseFloat(td.dataset.sort);
    if(s) return td.textContent.trim().toLowerCase();
    var n=parseFloat(td.textContent.replace(/[^0-9.eE-]/g,''));
    return isNaN(n)?-Infinity:n;
  }
  function sortBy(c,s,th){
    var d=(c===cc)?-cd:(s?1:-1); cc=c; cd=d;
    var rows=Array.prototype.slice.call(tb.rows);
    rows.sort(function(a,b){var x=val(a,c,s),y=val(b,c,s);return (x<y?-1:x>y?1:0)*d;});
    rows.forEach(function(r){tb.appendChild(r);});
    hs.forEach(function(h){h.classList.remove('asc','desc');});
    th.classList.add(d>0?'asc':'desc');
  }
  hs.forEach(function(h){
    h.addEventListener('click',function(){sortBy(parseInt(h.dataset.col,10), h.dataset.type==='str', h);});
  });
})();
</script>"""


