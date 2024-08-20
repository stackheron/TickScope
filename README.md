# TickScope

Offline timing and CPU-load analysis of embedded RTOS scheduling traces.
Pure Python 3 standard library; nothing talks to the target. Inputs are a packet
capture of a streamed trace or an InterpretedTraceData/RawTraceData CSV export, plus
the XML project file that describes the traced system (systems, tick duration,
task table, BSF event).

| script | input | output |
|--------|-------|--------|
| `stream_to_csv.py` | `.pcapng`/`.pcap` of an unattended trace stream | InterpretedTraceData CSV (+ optional RawTraceData CSV, `.bin`, timing report) |
| `timing_report.py`        | InterpretedTraceData CSV | per-task CET/DT/RT/ST + BSF CPU-load report (CSV, optional HTML) |
| `interpret.py`     | RawTraceData CSV or raw `.bin` trace block | InterpretedTraceData CSV |
| `posix_report.py`         | `.pcapng`/`.pcap` of a POSIX/QNX trace stream | per-CPU and per-process/thread BSF CPU-load report |

## Quick start

```sh
# capture -> InterpretedTraceData + timing report (CSV + HTML) in one go
python3 stream_to_csv.py --pcap stream.pcapng --project PROJ.xml --report --html

# report from an existing InterpretedTraceData CSV (e.g. exported by a host tool)
python3 timing_report.py --interp trace_InterpretedTraceData.csv --project PROJ.xml --html

# RawTraceData CSV -> InterpretedTraceData
python3 interpret.py --project PROJ.xml --sid 2 --raw-csv trace_RawTraceData.csv --out trace.csv
```

## Stream captures (`stream_to_csv.py`)

In unattended streaming the target broadcasts its trace continuously over
UDP, e.g. `<ECU_IP>:<EcuPort> -> 255.255.255.255:<PcPort>` (values from the project file).
Capture it with any sniffer (tcpdump, Wireshark) and convert it offline:

```sh
python3 stream_to_csv.py --pcap stream.pcapng --project PROJ.xml
# -> stream_InterpretedTraceData.csv   (--raw-out / --bin-out for RawTraceData / .bin)
#    --sid N picks a core; default = the core with the most captured entries
#    --list-cores lists the cores found in the capture and exits

# narrow a capture that holds more than one ECU/stream by endpoint (all optional):
#   --src-ip ECU IP   --dst-ip destination   --sport ECU <EcuPort>   --dport PC <PcPort>
python3 stream_to_csv.py --pcap both.pcapng --project PROJ.xml --src-ip <ECU_IP> --dport <PC_PORT>
```

Each stream is identified by the frame TargetId (mapped to a project SID), so the
cores of several ECUs in one capture are separated as long as their TargetIds differ.
The run prints each core's endpoint (`[src:sport -> dst:dport]`) to filter on.

Wire format (one UDP datagram = one or more concatenated frames):

- The trace rides in **trace-plugin (1), op 18** extended frames (`88 91 <len16 LE>`).
  Each payload is a 4-byte sub-header `[seq, 0x3c, 0x00, 0x00]` followed by an array
  of uint32 LE trace entries.
- `seq` is a per-core datagram counter (wraps at 256); a jump means a **dropped UDP
  datagram** (broadcast is lossy). The tool warns, and re-anchors the time across the
  gap from the capture clock so timestamp wraps lost in the gap are recovered.
- The stream is already chronological, so no ring/discontinuity reorder is needed.

The reader parses pcapng (SHB/IDB/EPB/SPB) and classic pcap and strips
Ethernet/VLAN/IPv4/UDP. Validated against a reference recording: the extracted
entries equal the host's RawTraceData and every InterpretedTraceData column is
identical except the wall-clock `Timestamp` the host adds on sync-data events.

A POSIX/QNX system in the project file is detected automatically and handed to
`posix_report.py` (use `--report` and/or `--html`).

## Trace entry format (MCU targets)

```
entry = (rawTime << 16) | (eventId << 10) | traceInfo
    bits[31:16] rawTime   16-bit rolling timestamp, unit = TickDuration (project)
    bits[15:10] eventId   1 START, 2 STOP, 12 ACTIVATION, 13 WAIT, 14 RESUME,
                          15 DISCONTINUITY, 18 SYNCDATA_START, 20/21 sync carriers, 24 TRIGGER
    bits[9:0]   traceInfo element id (Task/ISR) for scheduling events; control payload otherwise
```

Absolute time = unwrapped rawTime * TickDuration. Element names come from the project file
`<SystemElement ID=.. Name=.. Type="Task">` table. A raw `.bin` block read out of the
ring buffer is rotated so the DISCONTINUITY marker (write pointer) is last, which
gives chronological order (`--no-reorder` disables this).

## Timing report (`timing_report.py`)

Per task/ISR **min/avg/max of CET, DT, RT, ST** plus per-BSF-frame CPU load, using the
project file for element id/priority, tick and BSF event:

```sh
python3 timing_report.py --interp trace_InterpretedTraceData.csv --project PROJ.xml
python3 timing_report.py --interp trace_InterpretedTraceData.csv --project PROJ.xml --html
#   --raw-cet   report CET without trace-overhead compensation
#   --source / --captured  override the provenance shown in the report
```

| metric | name | definition |
|--------|------|------------|
| **CET** | Core Execution Time | on-CPU time per job (preemption/wait gaps excluded) |
| **DT**  | Delta Time | interval between consecutive Activations (observed period) |
| **RT**  | Response Time | `Stop - Activation` (release to termination) |
| **ST**  | Slack Time | `Activation(next) - Stop` (the gap; `= period - RT`) |
| **CPU Load [%]** | per-BSF-frame CPU load | `100 * (task CET in frame) / frame duration` |

One job = `Activation -> Start -> [Wait -> Resume]* -> Stop`; min/avg/max are over
the per-job population.

- **CET** includes trace-overhead compensation `TickDuration * (2 + 4*nwait)` per
  job (validated against a host System report: min/max exact for most tasks, avg
  within 1 us). `--raw-cet` gives the uncompensated value.
- **CPU load** is per **BSF frame** (interval between consecutive activations of the
  `<BasicSchedulingFrameEvent SystemElementID=..>` task from the project file). Execution
  straddling a frame boundary is split by time; frames where a task does not run count
  as 0 %. The system-level min/avg/max is in the report header.
- The **CSV** uses a decimal comma for percentages (host-report style); the **HTML**
  uses a dot. The HTML is self-contained (light/dark theme, click a column header to
  sort).
- Both carry provenance: source file, project file, build id, trace duration, capture time.

