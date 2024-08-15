#!/usr/bin/env python3
"""
Convert an unattended trace stream captured in a .pcapng/.pcap into
InterpretedTraceData (and optionally RawTraceData), using a
project file for element names and timing. No vendor host tool needed.

Unattended streaming has the target broadcast its trace continuously over
debug-Ethernet UDP, e.g. <ECU_IP>:<EcuPort> -> 255.255.255.255:<PcPort> (from the project file). Each UDP
datagram is one or more concatenated frames:

    std frame:  [b0] [b1] [6-byte payload]                       (8 bytes)
    ext frame:  [b0|0x80] [b1] [len16 LE] [len bytes payload]
        b0: bit7 = extended, bits[6:2] = (TargetId << 2)  -> tid = (b0 & 0x7F) >> 2
        b1: bits[7:3] = opcode, bits[2:0] = plugin

Trace data rides in trace-plugin frames (plugin 1, op 18). Their payload is a
4-byte sub-header [seq, 0x3c, 0x00, 0x00] (seq = per-core datagram counter, wraps
at 256 -> lets us spot dropped UDP packets) followed by an array of uint32 LE
trace-entry records. The stream is already chronological (continuous flush),
so unlike a ring-buffer read-out it needs NO ring/discontinuity reorder.

Validated byte-for-byte against a reference export: the extracted entries equal the host's
RawTraceData.csv and the interpreted rows equal its InterpretedTraceData.csv (the
only column we cannot reproduce is the wall-clock 'Timestamp' the host derives for
sync-data events from its own capture clock).

Shares the interpretation core in interpret.py.
"""

import argparse
import datetime
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import interpret as ti
import timing_report as tr

# trace-plugin trace-data frame (plugin, op)
TRACE_PLUGIN = 1
TRACE_STREAM_OP = 18


# --------------------------------------------------------------------------- #
# pcap / pcapng readers (stdlib only)
# --------------------------------------------------------------------------- #
def _iter_pcap(data):
    """Classic libpcap: yield (frame_offset, frame, linktype, capture_epoch)."""
    magic = data[:4]
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        en = ">"
    elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        en = "<"
    else:
        raise ValueError("not a classic pcap file")
    nano = magic in (b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1")
    linktype = struct.unpack_from(en + "I", data, 20)[0]
    off = 24
    while off + 16 <= len(data):
        ts_sec, ts_frac, incl, _ = struct.unpack_from(en + "IIII", data, off)
        off += 16
        yield off, data[off:off + incl], linktype, ts_sec + ts_frac / (1e9 if nano else 1e6)
        off += incl


def _iter_pcapng(data):
    """pcapng: yield (frame_offset, frame, linktype, capture_epoch or None)."""
    off = 0
    en = "<"
    ifaces = []                                         # (linktype, ts factor)
    while off + 12 <= len(data):
        btype = struct.unpack_from("<I", data, off)[0]
        if btype == 0x0A0D0D0A:  # Section Header Block -> (re)detect endianness
            bom = struct.unpack_from("<I", data, off + 8)[0]
            en = "<" if bom == 0x1A2B3C4D else ">"
            ifaces = []
        blen = struct.unpack_from(en + "I", data, off + 4)[0]
        if blen < 12 or off + blen > len(data):
            break
        body = data[off + 8: off + blen - 4]
        if btype == 0x00000001:  # Interface Description Block
            lt = struct.unpack_from(en + "H", body, 0)[0]
            factor, p = 1e-6, 8                         # default resolution = microseconds
            while p + 4 <= len(body):
                code, ln = struct.unpack_from(en + "HH", body, p)
                p += 4
                if code == 0:
                    break
                if code == 9 and ln >= 1:               # if_tsresol
                    r = body[p]
                    factor = (2.0 ** -(r & 0x7F)) if (r & 0x80) else (10.0 ** -r)
                p += (ln + 3) & ~3
            ifaces.append((lt, factor))
        elif btype == 0x00000006:  # Enhanced Packet Block
            ifid, tsh, tsl, incl, _ = struct.unpack_from(en + "IIIII", body, 0)
            lt, factor = ifaces[ifid] if ifid < len(ifaces) else (1, 1e-6)
            yield off + 28, body[20:20 + incl], lt, ((tsh << 32) | tsl) * factor
        elif btype == 0x00000003:  # Simple Packet Block (no timestamp)
            lt = ifaces[0][0] if ifaces else 1
            yield off + 12, body[4:], lt, None
        off += blen


def iter_frames(data):
    """Yield (frame_offset, frame, linktype, capture_epoch) from a pcap/pcapng image."""
    return _iter_pcapng(data) if data[:4] == b"\x0a\x0d\x0d\x0a" else _iter_pcap(data)


def _udp_payload(frame, linktype):
    """Strip link/IPv4/UDP; return (src_ip, dst_ip, sport, dport, payload, payload_offset)
    or None."""
    if linktype == 1:            # Ethernet II
        if len(frame) < 14:
            return None
        etype = struct.unpack_from(">H", frame, 12)[0]
        p = 14
        while etype in (0x8100, 0x88A8):   # VLAN tag(s)
            if len(frame) < p + 4:
                return None
            etype = struct.unpack_from(">H", frame, p + 2)[0]
            p += 4
        if etype != 0x0800:
            return None
    elif linktype in (101, 12):  # RAW IP
        p = 0
    else:
        return None
    ip = frame[p:]
    if len(ip) < 20 or (ip[0] >> 4) != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if ip[9] != 17 or len(ip) < ihl + 8:      # not UDP
        return None
    src_ip = ".".join(str(b) for b in ip[12:16])
    dst_ip = ".".join(str(b) for b in ip[16:20])
    sport, dport, ulen = struct.unpack_from(">HHH", ip, ihl)
    payload = ip[ihl + 8: ihl + max(ulen, 8)]
    return src_ip, dst_ip, sport, dport, payload, p + ihl + 8


def iter_udp(data):
    """Yield (frame_no, payload_offset, src_ip, dst_ip, sport, dport, payload,
    capture_epoch) for every UDP datagram; frame_no is 1-based over all packets and
    payload_offset is absolute in `data` (so callers can patch the image in place)."""
    for n, (foff, frame, lt, ts) in enumerate(iter_frames(data), 1):
        u = _udp_payload(frame, lt)
        if u is not None:
            src_ip, dst_ip, sport, dport, payload, poff = u
            yield n, foff + poff, src_ip, dst_ip, sport, dport, payload, ts


def read_udp_payloads(path):
    """Return [(src_ip, dst_ip, sport, dport, payload, capture_epoch)] for every UDP
    datagram."""
    data = open(path, "rb").read()
    return [u[2:] for u in iter_udp(data)]


def first_capture_epoch(path):
    """Return the first packet's capture time as a Unix epoch (float, UTC), or None."""
    try:
        data = open(path, "rb").read()
        return next((ts for _, _, _, ts in iter_frames(data) if ts is not None), None)
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Frame walk + trace-stream extraction
# --------------------------------------------------------------------------- #
def walk_frames(buf):
    """Yield (tid, plugin, op, payload) for concatenated frames in a datagram."""
    off = 0
    while off + 2 <= len(buf):
        b0, b1 = buf[off], buf[off + 1]
        tid = (b0 & 0x7F) >> 2
        op = (b1 >> 3) & 0x1F
        plugin = b1 & 0x07
        if b0 & 0x80:                                   # extended frame
            if off + 4 > len(buf):
                break
            ln = struct.unpack_from("<H", buf, off + 2)[0]
            if off + 4 + ln > len(buf):
                break
            yield tid, plugin, op, buf[off + 4: off + 4 + ln]
            off += 4 + ln
        else:                                           # standard 8-byte frame
            yield tid, plugin, op, buf[off + 2: off + 8]
            off += 8


def extract_streams(payloads, flt=None):
    """Return {tid: {'entries','gaps','frames','endpoint'}} from trace-stream frames.

    flt (optional): {'src_ip','dst_ip','sport','dport'} -- any set key restricts which
    UDP datagrams are accepted (None/absent = accept any). Lets a capture that holds
    more than one ECU/stream be narrowed to one endpoint."""
    flt = flt or {}
    cores = {}
    for src_ip, dst_ip, sport, dport, buf, ts in payloads:
        if flt.get("src_ip") and src_ip != flt["src_ip"]:
            continue
        if flt.get("dst_ip") and dst_ip != flt["dst_ip"]:
            continue
        if flt.get("sport") is not None and sport != flt["sport"]:
            continue
        if flt.get("dport") is not None and dport != flt["dport"]:
            continue
        for tid, plugin, op, payload in walk_frames(buf):
            if plugin != TRACE_PLUGIN or op != TRACE_STREAM_OP or len(payload) < 4:
                continue
            c = cores.setdefault(tid, {"entries": [], "gaps": 0, "frames": 0, "seq": None,
                                       "ts": None, "gap_hints": {},
                                       "endpoint": (src_ip, dst_ip, sport, dport)})
            body = payload[4:]
            n = len(body) // 4
            seq = payload[0]
            if c["seq"] is not None and (c["seq"] + 1) & 0xFF != seq:
                c["gaps"] += 1
                # dropped datagram(s): remember the capture-clock time between the last
                # entry before the gap and the last entry of this frame, so the
                # interpreter can recover 16-bit timestamp wraps lost in the gap
                if n and ts is not None and c["ts"] is not None:
                    start = len(c["entries"])
                    c["gap_hints"][start] = (start + n - 1, (ts - c["ts"]) * 1e9)
            c["seq"] = seq
            c["ts"] = ts
            c["frames"] += 1
            c["entries"].extend(struct.unpack(f"<{n}I", body[:n * 4]))
    for c in cores.values():
        c.pop("seq", None)
        c.pop("ts", None)
    return cores


def parse_project_tid_map(path):
    """Return {TargetId: sid} from the project file SystemCommunicationConfig."""
    import re
    xml = open(path, encoding="utf-8-sig").read()
    spans = [m.start() for m in re.finditer(r"<System\b", xml)] + [len(xml)]
    tid2sid = {}
    for i in range(len(spans) - 1):
        body = xml[spans[i]:spans[i + 1]]
        sid = re.search(r'SID="(\d+)"', body)
        tid = re.search(r"<TargetId>(\d+)</TargetId>", body)
        if sid and tid:
            tid2sid[int(tid.group(1))] = int(sid.group(1))
    return tid2sid


def write_raw_csv(entries, sid, path):
    cols = ["Raw Index", "Raw Time", "Event Id (dec)", "Event Id (hex)",
            "Trace Info (dec)", "Trace Info (hex)", "Raw Trace Entry", "System Id"]
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        f.write(";".join(cols) + "\n")
        for i, e in enumerate(entries, 1):
            ts, ev, info = (e >> 16) & 0xFFFF, (e >> 10) & 0x3F, e & 0x3FF
            f.write(f"{i};{ts};{ev};0x{ev:02X};{info};0x{info:03X};0x{e:08X};{sid}\n")


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(
        description="Convert an unattended trace stream (.pcapng/.pcap) to "
                    "InterpretedTraceData.csv")
    ap.add_argument("--pcap", required=True, help="capture file (.pcapng or .pcap)")
    ap.add_argument("--project", required=True, help="project file for names + timing")
    ap.add_argument("--sid", type=int, default=None,
                    help="system id to interpret (default: the core with most entries)")
    ap.add_argument("--src-ip", default=None,
                    help="only accept UDP datagrams from this source IP (the ECU, project <IpAddress>)")
    ap.add_argument("--dst-ip", default=None,
                    help="only accept UDP datagrams to this destination IP "
                         "(e.g. the 255.255.255.255 broadcast)")
    ap.add_argument("--sport", type=int, default=None,
                    help="only accept UDP datagrams from this source port (ECU <EcuPort>)")
    ap.add_argument("--dport", type=int, default=None,
                    help="only accept UDP datagrams to this port (PC <PcPort>)")
    ap.add_argument("--out", help="InterpretedTraceData CSV (default: <pcap>_InterpretedTraceData.csv)")
    ap.add_argument("--raw-out", nargs="?", const="", default=None,
                    help="also write a RawTraceData CSV (default name if no value given)")
    ap.add_argument("--bin-out", nargs="?", const="", default=None,
                    help="also write the raw uint32 LE trace block (.bin)")
    ap.add_argument("--report", nargs="?", const="", default=None,
                    help="also write a per-task CET/DT/RT/ST + CPU-load report CSV "
                         "(default name if no value given)")
    ap.add_argument("--html", nargs="?", const="", default=None,
                    help="also write the timing report as styled HTML "
                         "(default name if no value given)")
    ap.add_argument("--raw-cet", action="store_true",
                    help="with --report/--html: raw CET without trace-overhead compensation")
    ap.add_argument("--list-cores", action="store_true",
                    help="list the SIDs found in the capture (one 'sid tid entries name' "
                         "line each) and exit")
    args = ap.parse_args()

    payloads = read_udp_payloads(args.pcap)
    if not payloads:
        print(f"ERROR: no UDP datagrams in {args.pcap}", file=sys.stderr)
        return 2
    flt = {"src_ip": args.src_ip, "dst_ip": args.dst_ip,
           "sport": args.sport, "dport": args.dport}
    cores = extract_streams(payloads, flt)
    if not cores:
        active = ", ".join(f"{k}={v}" for k, v in flt.items() if v is not None)
        print(f"ERROR: no trace stream frames (plugin 1, op 18) found"
              + (f" matching filter [{active}]" if active else ""), file=sys.stderr)
        return 2

    systems = ti.parse_project(args.project)
    tid2sid = parse_project_tid_map(args.project)

    # map captured cores (by frame TargetId) to SIDs; pick which to interpret
    found = []
    for tid, c in cores.items():
        sid = tid2sid.get(tid, tid)
        found.append((sid, tid, c))
    found.sort(key=lambda x: -len(x[2]["entries"]))
    print(f"[stream] {len(payloads)} UDP datagrams; cores found:")
    for sid, tid, c in found:
        nm = systems.get(sid, {}).get("name", f"SID{sid}")
        sip, dip, sp, dp = c["endpoint"]
        print(f"    tid {tid} -> SID {sid} ({nm}): {len(c['entries'])} entries, "
              f"{c['frames']} frames, {c['gaps']} seq-gaps  [{sip}:{sp} -> {dip}:{dp}]")

    if args.list_cores:
        for sid, tid, c in found:
            print(f"{sid} {tid} {len(c['entries'])} "
                  f"{systems.get(sid, {}).get('name', f'SID{sid}')}")
        return 0

    if args.sid is not None:
        sel = next((x for x in found if x[0] == args.sid), None)
        if sel is None:
            print(f"ERROR: SID {args.sid} not in capture (have {[x[0] for x in found]})",
                  file=sys.stderr)
            return 2
    else:
        sel = found[0]
    sid, tid, c = sel
    entries, gaps = c["entries"], c["gaps"]
    if not entries:
        print(f"ERROR: SID {sid} has no trace entries in the capture", file=sys.stderr)
        return 2
    if sid not in systems:
        print(f"ERROR: SID {sid} not in the project file (have {sorted(systems)})", file=sys.stderr)
        return 2
    if gaps:
        print(f"WARNING: {gaps} dropped-datagram gap(s) in the stream -> the trace has "
              f"missing spans (a UDP broadcast is lossy); time across each gap is "
              f"re-anchored from the capture clock.", file=sys.stderr)

    sysinfo = systems[sid]
    sysinfo["sid"] = sid

    stem = os.path.splitext(args.pcap)[0]

    # A POSIX/QNX target uses a wider clock (MaxAbsTime=0xFFFFFF) and a completely
    # different 64-bit trace format (see posix_report.py). The MCU InterpretedTraceData
    # decode below does not apply; delegate the per-CPU/thread CPU-load report to
    # posix_report instead (byte-exact InterpretedTraceData for POSIX is not reproduced).
    if sysinfo["wrap"] > 0x10000:
        import posix_report as tp
        if args.report is None and args.html is None:
            print(f"ERROR: SID {sid} ({sysinfo['name']}) is a POSIX/QNX system; this tool "
                  f"reproduces its CPU-load report but not the InterpretedTraceData. "
                  f"Re-run with --report and/or --html.", file=sys.stderr)
            return 2
        repp = (args.report or f"{stem}_posix_report.csv") if args.report is not None else None
        htmlp = (args.html or f"{stem}_posix_report.html") if args.html is not None else None
        epoch = first_capture_epoch(args.pcap)
        captured = (datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
                    .strftime("%Y-%m-%d %H:%M:%S UTC")) if epoch else None
        meta = {"Source": os.path.basename(args.pcap), "Project": os.path.basename(args.project)}
        if captured:
            meta["Captured"] = captured
        cpu_stats, proc_rows, nf, mode = tp.report(payloads, args.project, sid, repp, meta,
                                                   html_path=htmlp, flt=flt)
        outs = " + ".join(p for p in (repp, htmlp) if p)
        lbl = "synthetic windows" if mode == "synthetic" else "BSF frames"
        print(f"[posix] {nf} {lbl}, {len(proc_rows)} processes -> {outs}")
        for c in sorted(cpu_stats):
            mn, av, mx, n = cpu_stats[c]
            print(f"    CPU{c}: min {mn:.2f}  avg {av:.2f}  max {mx:.2f}")
        return 0
    out = args.out or f"{stem}_InterpretedTraceData.csv"

    # stream is already chronological: no ring/discontinuity reorder (start_pos=0)
    rows = ti.interpret(entries, sysinfo, buf_base=None, start_pos=0,
                        gap_hints=c["gap_hints"])
    with open(out, "w", encoding="utf-8-sig", newline="") as f:
        f.write(";".join(ti.COLS) + "\n")
        for r in rows:
            f.write(";".join(str(r[cn]) for cn in ti.COLS) + "\n")
    print(f"[stream] {len(rows)} rows -> {out}  (system {sysinfo['name']}, "
          f"tick {sysinfo['tick']}ns, {len(entries)} raw entries)")

    if args.raw_out is not None:
        rawp = args.raw_out or f"{stem}_RawTraceData.csv"
        write_raw_csv(entries, sid, rawp)
        print(f"[stream] {len(entries)} raw entries -> {rawp}")
    if args.bin_out is not None:
        binp = args.bin_out or f"{stem}.bin"
        with open(binp, "wb") as f:
            f.write(struct.pack(f"<{len(entries)}I", *entries))
        print(f"[stream] raw block -> {binp}")
    if args.report is not None or args.html is not None:
        repp = (args.report or f"{stem}_report.csv") if args.report is not None else None
        htmlp = (args.html or f"{stem}_report.html") if args.html is not None else None
        epoch = first_capture_epoch(args.pcap)
        captured = (datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
                    .strftime("%Y-%m-%d %H:%M:%S UTC")) if epoch else None
        n, _ = tr.report_from_interp_rows(rows, args.project, sid, sysinfo["name"], repp,
                                          compensate=not args.raw_cet, html_path=htmlp,
                                          source=args.pcap, captured=captured)
        outs = " + ".join(p for p in (repp, htmlp) if p)
        print(f"[stream] {n} elements -> {outs}  (CET/DT/RT/ST + BSF CPU load, "
              f"CET {'raw' if args.raw_cet else 'overhead-compensated'})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
