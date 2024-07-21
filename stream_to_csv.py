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


