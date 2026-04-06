# Net Monitor — ISP Complaint Evidence Builder

## What this is
Single-file Python CLI tool (`net_monitor.py`) that continuously monitors network quality using TTL-based progressive hop-by-hop tracing. Produces hard evidence for ISP complaints/UKE reports.

## Architecture
- One file: `net_monitor.py`, zero pip dependencies
- Uses system tools: `traceroute`, `ping`, `curl`
- Data stored in `~/.net_monitor/`

## Data structure — per-session output directories

Each monitoring session creates a timestamped directory:

```
~/.net_monitor/
  output/
    20260405_143000/              # session started at 2026-04-05 14:30:00
      connection_info.json        # network config + ISP counterarguments
      events.jsonl                # AI-friendly event stream (PRIMARY)
      traceroute_raw.log          # raw traceroute output
      hop_log.csv                 # per-hop reached/failed per cycle
      incidents_log.csv           # fault zone incidents
      drops_log.csv               # full connectivity drops
      speed_log.csv               # speed test results
    20260405_180000/              # next session
      ...
  reports/                        # generated reports (JSON + Markdown)
```

### connection_info.json
Written once at session start. Contains:
- Full network config (interface, type, IP, gateway, DNS, MAC, MTU)
- WiFi details if applicable (SSID, RSSI, noise, channel, PHY mode, tx rate, security)
- ISP counterarguments with rebuttals and risk assessment
- Monitor configuration (targets, runs, thresholds)

### events.jsonl — AI-friendly event stream
Each line = one JSON event with `ts` and `type`:
- `session_start` — network_env, isp_counterarguments, config
- `cycle_start` — network_env snapshot (detects changes)
- `traceroute` — raw route discovery results
- `trace_cycle` — per-target: ok/fail runs, faults with hop/zone
- `drop_start` / `drop_end` — connectivity drops with duration and fault zone
- `cycle_end` — cycle summary
- `session_end` — full session stats

## Fault zone classification
- LOCAL (hop 1) — client router/WiFi
- ISP_EDGE (hop 2) — ISP's first device
- ISP_CORE (hop 3-4) — ISP backbone
- TRANSIT (hop 5+) — beyond ISP

## How tracing works
Each cycle runs `traceroute` to discover the route, then sends N probe runs.
Each run = one packet with increasing TTL (1,2,3...) — shows exactly which hop it passes through or drops at. Early exit on failure.

## Analysis with Claude Code / Cowork
To analyze collected data:
```
Przeanalizuj logi z ~/.net_monitor/ uzywajac prompta z analyze_prompt.md
```
Claude reads `connection_info.json` + `events.jsonl` from each session and produces diagnosis with ISP counterarguments.

## PR workflow
After completing all changes, always create a PR, functionally test the feature first, then run code review (CR) in a loop — fix all reported issues until CR returns no problems. Do not auto-merge — wait for explicit user approval before merging.

**CR is mandatory for every PR, regardless of change size.** Even documentation-only or single-line fixes must go through CR.
