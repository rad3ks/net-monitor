# Net Monitor

CLI tool that continuously monitors your internet connection quality and builds hard evidence for ISP complaints. Uses TTL-based hop-by-hop tracing to pinpoint exactly where packets drop — your router, ISP edge, ISP backbone, or beyond.

**Zero dependencies** — one Python file, system tools only.

## Quick Start

### macOS

```bash
# Prerequisites: Python 3.8+ (preinstalled), traceroute (preinstalled), curl (preinstalled)

# Clone and run
git clone https://github.com/rad3ks/net-monitor.git
cd net-monitor
sudo python3 net_monitor.py
```

> `sudo` is required because `traceroute` and TTL-based `ping` need raw socket access on macOS.

### Windows

**Wymagania:**
- Python 3.8+ — [python.org](https://www.python.org/downloads/) lub `winget install Python.Python.3.12`
- Git — [git-scm.com](https://git-scm.com/download/win) lub `winget install Git.Git`
- `tracert`, `ping`, `curl` — wbudowane w Windows 10+

**Instalacja i uruchomienie:**

1. Otwórz **PowerShell jako Administrator** (prawy klik na Start > "Terminal (Admin)" lub "Windows PowerShell (Admin)")

2. Wybierz folder i sklonuj repo:
```powershell
cd ~\Documents
git clone https://github.com/rad3ks/net-monitor.git
cd net-monitor
```

3. Uruchom monitoring:
```powershell
python net_monitor.py
```

4. Zatrzymaj: `Ctrl+C` — wyswietli podsumowanie sesji

5. Wygeneruj dashboard:
```powershell
python net_monitor.py --dashboard
```

> **Uwaga:** Uruchomienie jako Administrator jest wymagane — `tracert` i `ping` z niestandardowym TTL potrzebuja podwyzszonych uprawnien.

### Linux

```bash
# Prerequisites: Python 3.8+, traceroute (apt install traceroute), curl
sudo python3 net_monitor.py
```

## What It Does

Each monitoring cycle:

1. **traceroute** — discovers the route to target (hop by hop)
2. **TTL-based ping** — sends 10 probe runs per target, each with increasing TTL (1, 2, 3...) showing exactly which hop passes and which drops
3. **ping** — quick reachability check to additional targets
4. **curl** — periodic speed test

Real-time display shows each run as a line of dots — green = hop passed, red = hop dropped:

```
[14:30:00] google_dns (8.8.8.8) | 8 hops | 10 runs
  route: 192.168.1.1 > 10.0.0.1 > 72.14.215.85 > ... > 8.8.8.8
  #1   ●●●●●●●●  ✓ 14ms
  #2   ●●○        ✗ hop 3 [ISP_CORE] 72.14.215.85
  #3   ●●●●●●●●  ✓ 13ms
  8/10 OK (80%)  | faults: ISP_CORE:1
```

## Fault Zone Classification

| Zone | Hops | Meaning |
|------|------|---------|
| **LOCAL** | hop 1 | Your router / WiFi |
| **ISP_EDGE** | hop 2 | ISP's first device |
| **ISP_CORE** | hop 3-4 | ISP backbone |
| **TRANSIT** | hop 5+ | Beyond ISP |

If hop 1 is clean and problems start at hop 2+ — the ISP is at fault.

## Commands

```bash
python3 net_monitor.py                     # Run monitoring (Ctrl+C to stop)
python3 net_monitor.py --report            # Generate Markdown + JSON report
python3 net_monitor.py --dashboard         # Generate interactive HTML dashboard
python3 net_monitor.py --live              # Live dashboard (auto-refresh co 10s)
python3 net_monitor.py --live --port 9000  # Live dashboard on custom port
python3 net_monitor.py --list              # List all sessions
python3 net_monitor.py --clean             # Delete all collected data
python3 net_monitor.py --clean older --days 7  # Delete sessions older than 7 days
python3 net_monitor.py --help              # Full help
```

## Data

Each session creates a timestamped directory in `~/.net_monitor/output/`:

```
~/.net_monitor/
  output/
    20260405_143000/
      connection_info.json    # Network config + WiFi details + ISP counterarguments
      events.jsonl            # AI-friendly event stream (primary data file)
      traceroute_raw.log      # Raw traceroute output
      hop_log.csv             # Per-hop stats
      incidents_log.csv       # Fault zone incidents
      drops_log.csv           # Full connectivity drops
      speed_log.csv           # Speed tests
  reports/
    dashboard.html            # Interactive HTML dashboard
```

## Dashboard

Self-contained HTML file with:
- Session selector sidebar
- Success rate metrics + donut charts
- Per-hop/IP failure analysis
- WiFi signal (RSSI) history chart
- Failed runs with raw ping logs (false positive proof)
- Timeline visualization

```bash
python3 net_monitor.py --dashboard
```

### Live Dashboard

Auto-refreshing dashboard served via local HTTP server. Polls for new data every 10 seconds.

```bash
# Terminal 1: monitoring
python3 net_monitor.py

# Terminal 2: live dashboard
python3 net_monitor.py --live
```

**Updated** indicator in the sidebar shows time since last refresh and connection status.

## Safety

A PID-based lockfile prevents running two monitoring instances simultaneously (which would corrupt shared log files). If a previous process crashed, the stale lock is automatically cleaned up.

## AI Analysis

Feed collected data to Claude Code / Claude Cowork:

```
Przeanalizuj logi z ~/.net_monitor/ uzywajac prompta z analyze_prompt.md
```

## Platform Support

| Feature | macOS | Linux | Windows |
|---------|-------|-------|---------|
| TTL-based tracing | `ping -m` | `ping -t` | `ping -i` |
| Route discovery | `traceroute` | `traceroute` | `tracert` |
| Network info | `system_profiler`, `ifconfig` | `iw`, `ip` | `ipconfig`, `netsh wlan` |
| WiFi signal | RSSI (dBm) | RSSI (dBm) | Signal % (converted to dBm) |
| Speed test | `curl` | `curl` | `curl.exe` (Win10+) |

## License

MIT
