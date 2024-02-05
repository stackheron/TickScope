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

