#!/usr/bin/env python3
"""
Net Monitor -- ISP Complaint Evidence Builder
==============================================
TTL-based progressive hop-by-hop tracing with real-time display.
Each probe run sends a packet through the full chain of hops — you see
exactly where it gets through and where it drops.

Data dir: ~/.net_monitor/
  - traceroute_raw.log   — raw traceroute output (surówka)
  - events.jsonl         — machine-readable event stream (AI-friendly)
  - hop_log.csv          — per-hop stats per cycle
  - incidents_log.csv    — fault zone incidents
  - drops_log.csv        — full connectivity drops
  - speed_log.csv        — speed test results

Usage:
  python3 net_monitor.py                     # Run monitoring (continuous)
  python3 net_monitor.py --report            # Generate report (default 30 days)
  python3 net_monitor.py --report --days 7   # Report for last 7 days
"""

VERSION = "1.0.0"

import subprocess
import time
import csv
import json
import os
import sys
import re
import signal
import argparse
import math
import socket
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict

# ── Configuration ─────────────────────────────────────────────────────────

TRACE_TARGETS = {
    "google_dns": "8.8.8.8",
    "cloudflare_dns": "1.1.1.1",
}

PING_TARGETS = {
    "google_web": "google.com",
    "cloudflare_web": "cloudflare.com",
    "aws": "amazon.com",
}

RUNS_PER_TARGET = 10      # probe runs per target per cycle
MAX_HOPS = 15             # max TTL
PING_TIMEOUT = 2          # seconds per single probe
PAUSE_BETWEEN_RUNS = 1.0  # seconds between runs (min 1s)
SPEED_TEST_INTERVAL = 900
LOSS_THRESHOLD = 5.0      # % loss to flag a hop
STATS_EVERY_N_CYCLES = 5

DATA_DIR = Path.home() / ".net_monitor"
OUTPUT_DIR = DATA_DIR / "output"
REPORT_DIR = DATA_DIR / "reports"

# Per-session paths — set in setup_session_dir()
SESSION_DIR = None
TRACEROUTE_RAW = None
EVENTS_LOG = None
HOP_LOG = None
INCIDENTS_LOG = None
DROPS_LOG = None
SPEED_LOG = None
CONNECTION_INFO = None

IS_MACOS = sys.platform == "darwin"
IS_WINDOWS = sys.platform == "win32"
PLATFORM_NAME = "macOS" if IS_MACOS else "Windows" if IS_WINDOWS else "Linux"

# ── ANSI Colors ───────────────────────────────────────────────────────────

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"
BG_RED = "\033[41m"
WHITE = "\033[97m"


def _enable_windows_vt():
    """Enable ANSI escape code processing on Windows console."""
    if not IS_WINDOWS:
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_ulong()
        kernel32.GetConsoleMode(handle, ctypes.byref(mode))
        kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        pass

_enable_windows_vt()

# ── Helpers ───────────────────────────────────────────────────────────────

LOCKFILE = None  # set in acquire_lock()


def ensure_dirs():
    DATA_DIR.mkdir(exist_ok=True)
    OUTPUT_DIR.mkdir(exist_ok=True)
    REPORT_DIR.mkdir(exist_ok=True)


def acquire_lock():
    """Prevent multiple monitor instances from running simultaneously.
    Uses a PID-based lockfile in DATA_DIR. Returns True if lock acquired."""
    global LOCKFILE
    lock_path = DATA_DIR / "monitor.lock"

    # Check existing lock
    if lock_path.exists():
        try:
            content = lock_path.read_text().strip()
            old_pid = int(content)
            # Check if process is still alive
            if _pid_alive(old_pid):
                print(f"{RED}Net Monitor juz dziala (PID {old_pid}).{RESET}")
                print(f"{DIM}Jesli to blad, usun reczne: {lock_path}{RESET}")
                return False
            else:
                # Stale lock — previous process died
                lock_path.unlink()
        except (ValueError, OSError):
            # Corrupted lock — remove
            try:
                lock_path.unlink()
            except OSError:
                pass

    # Write our PID
    try:
        lock_path.write_text(str(os.getpid()))
        LOCKFILE = lock_path
        return True
    except OSError as e:
        print(f"{RED}Nie mozna utworzyc lockfile: {e}{RESET}")
        return False


def release_lock():
    """Release the lockfile."""
    global LOCKFILE
    if LOCKFILE and LOCKFILE.exists():
        try:
            LOCKFILE.unlink()
        except OSError:
            pass
        LOCKFILE = None


def _pid_alive(pid):
    """Check if a process with given PID is alive."""
    if IS_WINDOWS:
        try:
            r = subprocess.run(["tasklist", "/FI", f"PID eq {pid}"],
                               capture_output=True, text=True, timeout=5)
            return str(pid) in r.stdout
        except Exception:
            return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True  # alive but owned by another user


def setup_session_dir():
    """Create per-session output directory and set global file paths."""
    global SESSION_DIR, TRACEROUTE_RAW, EVENTS_LOG, HOP_LOG
    global INCIDENTS_LOG, DROPS_LOG, SPEED_LOG, CONNECTION_INFO

    session_name = datetime.now().strftime("%Y%m%d_%H%M%S")
    SESSION_DIR = OUTPUT_DIR / session_name
    SESSION_DIR.mkdir(parents=True, exist_ok=True)

    TRACEROUTE_RAW = SESSION_DIR / "traceroute_raw.log"
    EVENTS_LOG = SESSION_DIR / "events.jsonl"
    HOP_LOG = SESSION_DIR / "hop_log.csv"
    INCIDENTS_LOG = SESSION_DIR / "incidents_log.csv"
    DROPS_LOG = SESSION_DIR / "drops_log.csv"
    SPEED_LOG = SESSION_DIR / "speed_log.csv"
    CONNECTION_INFO = SESSION_DIR / "connection_info.json"

    return SESSION_DIR


def write_connection_info(net_env, isp_args):
    """Write connection_info.json describing the network configuration."""
    info = {
        "session_start": ts_iso(),
        "hostname": _run_cmd(["hostname"]),
        "platform": sys.platform,
        "platform_name": PLATFORM_NAME,
        "python_version": sys.version,
        "network": net_env,
        "isp_counterarguments": isp_args,
        "monitor_config": {
            "trace_targets": TRACE_TARGETS,
            "ping_targets": PING_TARGETS,
            "runs_per_target": RUNS_PER_TARGET,
            "max_hops": MAX_HOPS,
            "loss_threshold": LOSS_THRESHOLD,
            "pause_between_runs": PAUSE_BETWEEN_RUNS,
        },
    }
    try:
        with open(CONNECTION_INFO, "w") as f:
            json.dump(info, f, indent=2, default=str)
    except OSError:
        pass


def ts_now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def ts_short():
    return datetime.now().strftime("%H:%M:%S")


def ts_iso():
    return datetime.now().isoformat()


def is_private_ip(ip):
    if not ip or ip == "???":
        return False
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        a, b = int(parts[0]), int(parts[1])
        return (a == 10 or (a == 172 and 16 <= b <= 31) or
                (a == 192 and b == 168) or (a == 169 and b == 254))
    except (ValueError, IndexError):
        return False


def classify_hop(hop_num):
    if hop_num == 1:
        return "LOCAL"
    elif hop_num == 2:
        return "ISP_EDGE"
    elif hop_num in (3, 4):
        return "ISP_CORE"
    else:
        return "TRANSIT"


def find_gateway():
    try:
        if IS_MACOS:
            r = subprocess.run(["route", "-n", "get", "default"],
                               capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                if "gateway:" in line.lower():
                    return line.split(":")[-1].strip()
        elif IS_WINDOWS:
            r = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                if "default gateway" in line.lower():
                    m = re.search(r':\s*(\d+\.\d+\.\d+\.\d+)', line)
                    if m:
                        return m.group(1)
        else:
            r = subprocess.run(["ip", "route", "show", "default"],
                               capture_output=True, text=True, timeout=5)
            parts = r.stdout.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    except Exception:
        pass
    return None


# ── Network Environment ──────────────────────────────────────────────────

def _run_cmd(cmd, timeout=5):
    """Run a command, return stdout or empty string."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""


def gather_network_env():
    """Gather full network environment info.
    Returns dict with connection details — logged in full to events.jsonl,
    shown condensed in CLI.
    """
    env = {
        "interface": None,
        "interface_type": None,  # wifi / ethernet / other
        "ip": None,
        "subnet": None,
        "gateway": None,
        "dns_servers": [],
        "mac": None,
        "mtu": None,
        # WiFi-specific
        "wifi_ssid": None,
        "wifi_rssi_dbm": None,
        "wifi_noise_dbm": None,
        "wifi_channel": None,
        "wifi_phy_mode": None,
        "wifi_tx_rate": None,
        "wifi_security": None,
        # Ethernet-specific
        "eth_media": None,
    }

    if IS_MACOS:
        _gather_macos(env)
    elif IS_WINDOWS:
        _gather_windows(env)
    else:
        _gather_linux(env)

    return env


def _gather_macos(env):
    # Active interface from default route
    out = _run_cmd(["route", "-n", "get", "default"])
    for line in out.splitlines():
        low = line.strip().lower()
        if low.startswith("gateway:"):
            env["gateway"] = line.split(":")[-1].strip()
        elif low.startswith("interface:"):
            env["interface"] = line.split(":")[-1].strip()

    iface = env["interface"] or "en0"

    # IP + subnet from ifconfig
    out = _run_cmd(["ifconfig", iface])
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("inet ") and "inet6" not in line:
            parts = line.split()
            env["ip"] = parts[1] if len(parts) > 1 else None
            if "netmask" in line:
                idx = parts.index("netmask")
                if idx + 1 < len(parts):
                    hex_mask = parts[idx + 1]
                    try:
                        mask_int = int(hex_mask, 16)
                        env["subnet"] = ".".join(
                            str((mask_int >> (8 * i)) & 0xFF)
                            for i in [3, 2, 1, 0]
                        )
                    except ValueError:
                        env["subnet"] = hex_mask
        elif line.startswith("ether "):
            env["mac"] = line.split()[1] if len(line.split()) > 1 else None
        elif line.startswith("media:"):
            env["eth_media"] = line.split(":", 1)[-1].strip()
        elif "mtu " in line:
            m = re.search(r'mtu\s+(\d+)', line)
            if m:
                env["mtu"] = m.group(1)

    # DNS servers
    out = _run_cmd(["scutil", "--dns"])
    dns_found = set()
    for line in out.splitlines():
        m = re.match(r'\s*nameserver\[\d+\]\s*:\s*(\S+)', line)
        if m:
            ip = m.group(1)
            if ip not in dns_found:
                dns_found.add(ip)
                env["dns_servers"].append(ip)
                if len(dns_found) >= 4:
                    break

    # Detect interface type from hardware ports
    out = _run_cmd(["networksetup", "-listallhardwareports"])
    port_map = {}  # device -> hardware port name
    current_port = None
    for line in out.splitlines():
        if line.startswith("Hardware Port:"):
            current_port = line.split(":", 1)[-1].strip()
        elif line.startswith("Device:") and current_port:
            dev = line.split(":", 1)[-1].strip()
            port_map[dev] = current_port

    hw_port = port_map.get(iface, "")
    if "wi-fi" in hw_port.lower():
        env["interface_type"] = "wifi"
    elif "ethernet" in hw_port.lower() or "thunderbolt" in hw_port.lower():
        env["interface_type"] = "ethernet"
    else:
        env["interface_type"] = hw_port.lower() if hw_port else "unknown"

    # WiFi details from system_profiler
    if env["interface_type"] == "wifi":
        out = _run_cmd(["system_profiler", "SPAirPortDataType"], timeout=10)
        in_current = False
        ssid_next = False
        for line in out.splitlines():
            stripped = line.strip()
            if "Current Network Information:" in stripped:
                in_current = True
                ssid_next = True
                continue
            if in_current and ssid_next and stripped.endswith(":"):
                env["wifi_ssid"] = stripped[:-1]
                ssid_next = False
                continue
            if in_current:
                if "PHY Mode:" in stripped:
                    env["wifi_phy_mode"] = stripped.split(":", 1)[-1].strip()
                elif "Channel:" in stripped:
                    env["wifi_channel"] = stripped.split(":", 1)[-1].strip()
                elif "Signal / Noise:" in stripped:
                    val = stripped.split(":", 1)[-1].strip()
                    m = re.match(r'(-?\d+)\s*dBm\s*/\s*(-?\d+)\s*dBm', val)
                    if m:
                        env["wifi_rssi_dbm"] = int(m.group(1))
                        env["wifi_noise_dbm"] = int(m.group(2))
                elif "Transmit Rate:" in stripped:
                    env["wifi_tx_rate"] = stripped.split(":", 1)[-1].strip()
                elif "Security:" in stripped:
                    env["wifi_security"] = stripped.split(":", 1)[-1].strip()
                elif stripped == "" or (not stripped.startswith(" ") and ":" not in stripped):
                    in_current = False


def _gather_linux(env):
    # Active interface + gateway
    out = _run_cmd(["ip", "route", "show", "default"])
    parts = out.split()
    if "via" in parts:
        env["gateway"] = parts[parts.index("via") + 1]
    if "dev" in parts:
        env["interface"] = parts[parts.index("dev") + 1]

    iface = env["interface"] or "eth0"

    # IP + subnet
    out = _run_cmd(["ip", "-4", "addr", "show", iface])
    m = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', out)
    if m:
        env["ip"] = m.group(1)
        prefix = int(m.group(2))
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        env["subnet"] = ".".join(str((mask >> (8 * i)) & 0xFF) for i in [3, 2, 1, 0])

    # MAC
    m = re.search(r'link/ether\s+(\S+)', out)
    if m:
        env["mac"] = m.group(1)

    # MTU
    m = re.search(r'mtu\s+(\d+)', out)
    if m:
        env["mtu"] = m.group(1)

    # DNS
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                if line.strip().startswith("nameserver"):
                    ip = line.split()[1]
                    env["dns_servers"].append(ip)
    except Exception:
        pass

    # Interface type — check for wireless
    out = _run_cmd(["iw", "dev", iface, "info"])
    if out:
        env["interface_type"] = "wifi"
        for line in out.splitlines():
            if "ssid" in line.lower():
                env["wifi_ssid"] = line.split()[-1]
            elif "channel" in line.lower():
                env["wifi_channel"] = line.split("channel")[-1].strip()
    else:
        out = _run_cmd(["ethtool", iface])
        if "Speed:" in out:
            env["interface_type"] = "ethernet"
            for line in out.splitlines():
                if "Speed:" in line:
                    env["eth_media"] = line.split(":")[-1].strip()
        else:
            env["interface_type"] = "unknown"

    # WiFi signal
    if env["interface_type"] == "wifi":
        out = _run_cmd(["iw", "dev", iface, "link"])
        for line in out.splitlines():
            if "signal:" in line.lower():
                m = re.search(r'(-?\d+)', line)
                if m:
                    env["wifi_rssi_dbm"] = int(m.group(1))
            elif "tx bitrate:" in line.lower():
                env["wifi_tx_rate"] = line.split(":")[-1].strip()


def _gather_windows(env):
    """Gather network environment on Windows using ipconfig and netsh.
    Note: ipconfig field names are English — localized Windows may need PowerShell fallback.
    """
    # --- ipconfig /all — IP, gateway, DNS, MAC, interface ---
    out = _run_cmd(["ipconfig", "/all"], timeout=10)

    current_adapter = None
    adapters = {}  # adapter_name -> {field: value}

    for line in out.splitlines():
        # Adapter header: no leading whitespace, ends with ":"
        if not line.startswith(" ") and line.strip().endswith(":"):
            current_adapter = line.strip().rstrip(":")
            adapters[current_adapter] = {}
            continue
        if current_adapter and ":" in line:
            key, _, val = line.partition(":")
            key = key.strip().rstrip(".")
            val = val.strip()
            if val:
                adapters[current_adapter].setdefault(key.lower(), val)

    # Find adapter with a default gateway
    active_adapter = None
    for name, fields in adapters.items():
        gw = fields.get("default gateway", "")
        if gw and re.match(r'\d+\.\d+\.\d+\.\d+', gw):
            active_adapter = name
            break

    if active_adapter:
        fields = adapters[active_adapter]
        env["interface"] = active_adapter
        env["gateway"] = fields.get("default gateway")

        # IPv4 Address — may have "(Preferred)" suffix
        ipv4 = fields.get("ipv4 address",
                          fields.get("autoconfiguration ipv4 address", ""))
        if ipv4:
            env["ip"] = re.sub(r'\(.*\)', '', ipv4).strip()

        env["subnet"] = fields.get("subnet mask")

        mac = fields.get("physical address", "")
        if mac:
            env["mac"] = mac.replace("-", ":").lower()

        # MTU via netsh
        mtu_out = _run_cmd(["netsh", "interface", "ipv4", "show", "subinterfaces"])
        for mtu_line in mtu_out.splitlines():
            if active_adapter.lower() in mtu_line.lower():
                m = re.search(r'(\d+)', mtu_line)
                if m:
                    env["mtu"] = m.group(1)
                break

        # DNS servers (may span multiple lines)
        in_dns = False
        for line in out.splitlines():
            stripped = line.strip()
            if "dns servers" in line.lower() and ":" in line:
                in_dns = True
                ip = line.split(":")[-1].strip()
                if ip and re.match(r'\d+\.\d+\.\d+\.\d+', ip):
                    if ip not in env["dns_servers"]:
                        env["dns_servers"].append(ip)
                continue
            if in_dns:
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', stripped):
                    if stripped not in env["dns_servers"]:
                        env["dns_servers"].append(stripped)
                else:
                    in_dns = False

        # Interface type from adapter name
        name_lower = active_adapter.lower()
        if any(w in name_lower for w in ("wi-fi", "wireless", "wlan")):
            env["interface_type"] = "wifi"
        elif any(w in name_lower for w in ("ethernet", "local area connection")):
            env["interface_type"] = "ethernet"
        else:
            env["interface_type"] = "unknown"

    # --- WiFi details via netsh wlan show interfaces ---
    if env["interface_type"] == "wifi":
        wlan_out = _run_cmd(["netsh", "wlan", "show", "interfaces"])
        for line in wlan_out.splitlines():
            low = line.strip().lower()
            if low.startswith("ssid") and "bssid" not in low:
                env["wifi_ssid"] = line.split(":", 1)[-1].strip()
            elif low.startswith("signal"):
                m = re.search(r'(\d+)%', line)
                if m:
                    # Windows reports %, approximate to dBm: dBm ~ (pct/2) - 100
                    env["wifi_rssi_dbm"] = int(int(m.group(1)) / 2 - 100)
            elif low.startswith("channel"):
                env["wifi_channel"] = line.split(":", 1)[-1].strip()
            elif low.startswith("radio type"):
                env["wifi_phy_mode"] = line.split(":", 1)[-1].strip()
            elif low.startswith("transmit rate"):
                env["wifi_tx_rate"] = line.split(":", 1)[-1].strip()
            elif low.startswith("authentication"):
                env["wifi_security"] = line.split(":", 1)[-1].strip()


def print_network_env_short(env):
    """Print condensed network info to CLI."""
    itype = env.get("interface_type", "?")
    iface = env.get("interface", "?")
    ip = env.get("ip", "?")
    gw = env.get("gateway", "?")

    parts = [f"{iface} ({itype})", f"IP: {ip}", f"GW: {gw}"]

    if itype == "wifi":
        ssid = env.get("wifi_ssid", "?")
        rssi = env.get("wifi_rssi_dbm")
        ch = env.get("wifi_channel", "?")
        phy = env.get("wifi_phy_mode", "?")
        rssi_str = f"{rssi}dBm" if rssi is not None else "?"

        # Signal quality indicator
        if rssi is not None:
            if rssi >= -50:
                sig_color = GREEN
                sig_label = "excellent"
            elif rssi >= -60:
                sig_color = GREEN
                sig_label = "good"
            elif rssi >= -70:
                sig_color = YELLOW
                sig_label = "fair"
            else:
                sig_color = RED
                sig_label = "weak"
        else:
            sig_color = DIM
            sig_label = "?"

        parts.append(f"WiFi: {ssid}")
        parts.append(f"Signal: {sig_color}{rssi_str} ({sig_label}){RESET}")
        parts.append(f"Ch: {ch}")
        parts.append(f"PHY: {phy}")
    elif itype == "ethernet":
        media = env.get("eth_media", "?")
        parts.append(f"Media: {media}")

    dns = env.get("dns_servers", [])
    if dns:
        parts.append(f"DNS: {', '.join(dns[:2])}")

    print(f"  {DIM}{' | '.join(parts)}{RESET}")


def get_isp_counterarguments(env):
    """Return list of potential ISP counterarguments and our rebuttals
    based on current network config. Logged for AI analysis."""
    issues = []

    itype = env.get("interface_type", "unknown")
    rssi = env.get("wifi_rssi_dbm")

    if itype == "wifi":
        issues.append({
            "isp_argument": "Uzywasz WiFi, problem moze byc w zasiegu bezprzewodowym",
            "our_data": f"Interface: {env.get('interface')}, "
                        f"SSID: {env.get('wifi_ssid')}, "
                        f"Signal: {rssi}dBm, "
                        f"Channel: {env.get('wifi_channel')}, "
                        f"PHY: {env.get('wifi_phy_mode')}",
            "rebuttal": "Sygnal WiFi jest monitorowany i logowany. "
                        "Hop 1 (router) wykazuje stabilne 0% loss, "
                        "co dowodzi ze polaczenie WiFi dziala poprawnie. "
                        "Problem zaczyna sie na hop 2+ (infrastruktura ISP)."
                        + (f" RSSI {rssi}dBm jest w zakresie normalnym." if rssi and rssi >= -70 else ""),
            "risk": "low" if rssi and rssi >= -70 else "medium",
        })
        if rssi is not None and rssi < -75:
            issues.append({
                "isp_argument": "Sygnal WiFi jest slaby",
                "our_data": f"RSSI: {rssi}dBm (weak)",
                "rebuttal": "Nawet przy slabym sygnale WiFi, hop 1 pokazuje stabilne "
                            "polaczenie. Gdyby WiFi bylo przyczyna, to hop 1 mialby "
                            "podwyzszone loss, a tak nie jest.",
                "risk": "medium",
            })
    elif itype == "ethernet":
        issues.append({
            "isp_argument": "Problem moze byc w kablu Ethernet",
            "our_data": f"Interface: {env.get('interface')}, Media: {env.get('eth_media')}",
            "rebuttal": "Polaczenie kablowe (Ethernet) eliminuje zmiennosc WiFi. "
                        "Hop 1 (router) ma 0% loss — kabel dziala poprawnie.",
            "risk": "very_low",
        })

    # DNS
    dns = env.get("dns_servers", [])
    gw = env.get("gateway")
    if dns and gw and gw in dns:
        issues.append({
            "isp_argument": "Uzywasz DNS od routera/ISP, moze to problem DNS",
            "our_data": f"DNS: {', '.join(dns)}",
            "rebuttal": "Testy opieraja sie na ICMP ping/traceroute, nie DNS. "
                        "Cele testowe (8.8.8.8, 1.1.1.1) sa adresowane po IP, "
                        "wiec DNS nie wplywa na wyniki.",
            "risk": "none",
        })

    issues.append({
        "isp_argument": "Problem moze byc w routerze klienta",
        "our_data": f"Gateway: {gw}, Hop 1 loss monitorowany w kazdym cyklu",
        "rebuttal": "Kazdy cykl testowy sprawdza hop 1 (router). "
                    "Jesli hop 1 ma 0% loss a hop 2+ gubi pakiety, "
                    "to router dziala poprawnie a problem jest w sieci ISP.",
        "risk": "low",
    })

    return issues


# ── Logging ───────────────────────────────────────────────────────────────

def log_raw_traceroute(ts, target_name, target, output):
    """Append raw traceroute output to log file."""
    try:
        with open(TRACEROUTE_RAW, "a") as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"[{ts}] traceroute {target_name} ({target})\n")
            f.write(f"{'='*60}\n")
            f.write(output)
            f.write("\n")
    except OSError:
        pass


def log_event(event_type, data):
    """Append a JSON event to the events log (AI-friendly)."""
    event = {
        "ts": ts_iso(),
        "type": event_type,
        **data,
    }
    try:
        with open(EVENTS_LOG, "a") as f:
            f.write(json.dumps(event, default=str) + "\n")
    except OSError:
        pass


def init_csv():
    files_headers = {
        HOP_LOG: [
            "timestamp", "cycle", "target", "hop_num", "hop_host", "hop_zone",
            "reached", "failed_here", "rtt_ms",
        ],
        INCIDENTS_LOG: [
            "timestamp", "cycle", "target", "fault_zone", "fault_hop",
            "fault_host", "detail",
        ],
        DROPS_LOG: [
            "drop_start", "drop_end", "duration_seconds", "fault_zone", "detail",
        ],
        SPEED_LOG: [
            "timestamp", "test_name", "speed_mbps", "time_seconds", "http_code",
            "dns_ms", "connect_ms", "tls_ms", "ttfb_ms",
        ],
    }
    for path, headers in files_headers.items():
        if not path.exists():
            try:
                with open(path, "w", newline="") as f:
                    csv.writer(f).writerow(headers)
            except OSError:
                pass


def csv_append(path, row):
    try:
        with open(path, "a", newline="") as f:
            csv.writer(f).writerow(row)
    except OSError:
        pass


# ── Network Probes ────────────────────────────────────────────────────────

def discover_route(target):
    """Run traceroute, return (hops_list, raw_output).
    hops_list: [{hop_num, host}]
    """
    try:
        if IS_WINDOWS:
            cmd = ["tracert", "-d", "-h", str(MAX_HOPS), "-w", "2000", target]
        else:
            cmd = ["traceroute", "-n", "-q", "1", "-m", str(MAX_HOPS),
                   "-w", "2", target]
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=MAX_HOPS * 5 + 10)
        raw = result.stdout
        hops = []
        for line in raw.splitlines():
            if IS_WINDOWS:
                # tracert: "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"
                m = re.match(r'^\s*(\d+)\s+.*?(\d+\.\d+\.\d+\.\d+)\s*$', line)
                if m:
                    hops.append({"hop_num": int(m.group(1)), "host": m.group(2)})
                elif re.match(r'^\s*(\d+)\s+', line) and ("request timed out" in line.lower() or "*" in line):
                    m2 = re.match(r'^\s*(\d+)', line)
                    if m2:
                        hops.append({"hop_num": int(m2.group(1)), "host": "???"})
            else:
                m = re.match(r'^\s*(\d+)\s+(\S+)', line)
                if m:
                    hop_num = int(m.group(1))
                    host = m.group(2)
                    if host == "*":
                        host = "???"
                    hops.append({"hop_num": hop_num, "host": host})
        return hops, raw
    except Exception as e:
        return [], f"traceroute failed: {e}\n"


def ttl_ping(target, ttl):
    """Send one ping with specific TTL.
    Returns: (status, hop_ip, rtt_ms, raw_output)
      status: 'reached' | 'ttl_exceeded' | 'timeout'
      hop_ip: IP that responded (or None)
      rtt_ms: round-trip time (or None)
      raw_output: raw stdout+stderr from ping command
    """
    try:
        if IS_MACOS:
            cmd = ["ping", "-c", "1", "-m", str(ttl), "-W", "2000", target]
        elif IS_WINDOWS:
            cmd = ["ping", "-n", "1", "-i", str(ttl), "-w",
                   str(PING_TIMEOUT * 1000), target]
        else:
            cmd = ["ping", "-c", "1", "-t", str(ttl), "-W", "2", target]

        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=PING_TIMEOUT + 2)
        output = result.stdout + " " + result.stderr
        raw = output.strip()

        # Check if reached target (success)
        if result.returncode == 0:
            rtt = None
            m = re.search(r'time[=<]\s*([\d.]+)', output)
            if m:
                rtt = float(m.group(1))
            return "reached", target, rtt, raw

        # Check for TTL exceeded
        low = output.lower()
        if "time to live exceeded" in low or "ttl expired" in low:
            m = re.search(r'[Ff]rom\s+(\d+\.\d+\.\d+\.\d+)', output)
            hop_ip = m.group(1) if m else "???"
            return "ttl_exceeded", hop_ip, None, raw

        # No response
        return "timeout", None, None, raw

    except subprocess.TimeoutExpired:
        return "timeout", None, None, "TIMEOUT (subprocess)"
    except Exception as e:
        return "timeout", None, None, f"ERROR: {e}"


def estimate_speed():
    try:
        url = "https://speed.cloudflare.com/__down?bytes=10000000"
        null_dev = "NUL" if IS_WINDOWS else "/dev/null"
        cmd = ["curl", "-o", null_dev, "-s", "-w",
               "%{speed_download} %{time_total} %{http_code}"
               " %{time_namelookup} %{time_connect} %{time_appconnect} %{time_starttransfer}",
               "--max-time", "30", url]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=35)
        parts = r.stdout.strip().split()
        if len(parts) >= 3:
            result = {
                "test_name": "cloudflare_10MB",
                "speed_mbps": round(float(parts[0]) * 8 / 1_000_000, 2),
                "time_seconds": float(parts[1]),
                "http_code": parts[2],
            }
            if len(parts) >= 7:
                result["dns_ms"] = round(float(parts[3]) * 1000, 1)
                result["connect_ms"] = round(float(parts[4]) * 1000, 1)
                result["tls_ms"] = round(float(parts[5]) * 1000, 1)
                result["ttfb_ms"] = round(float(parts[6]) * 1000, 1)
            return result
    except Exception:
        pass
    return None


UPLOAD_TEST_SIZE = 2_000_000  # 2MB


def estimate_upload_speed():
    """Upload speed test using Cloudflare endpoint."""
    import tempfile
    tmp_path = None
    try:
        # Generate random payload to temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
            tmp.write(os.urandom(UPLOAD_TEST_SIZE))
            tmp_path = tmp.name
        url = "https://speed.cloudflare.com/__up"
        cmd = ["curl", "-s", "-X", "POST", "-F", f"file=@{tmp_path}", "-w",
               "%{speed_upload} %{time_total} %{http_code}",
               "-o", "NUL" if IS_WINDOWS else "/dev/null",
               "--max-time", "30", url]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=35)
        parts = r.stdout.strip().split()
        if len(parts) >= 3:
            return {
                "test_name": "cloudflare_upload_2MB",
                "speed_mbps": round(float(parts[0]) * 8 / 1_000_000, 2),
                "time_seconds": float(parts[1]),
                "http_code": parts[2],
            }
    except Exception:
        pass
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    return None


DNS_TEST_DOMAINS = ["google.com", "cloudflare.com", "amazon.com"]


def test_dns_resolution():
    """Measure DNS resolution time using system resolver."""
    results = []
    for domain in DNS_TEST_DOMAINS:
        start = time.time()
        try:
            socket.getaddrinfo(domain, 80, socket.AF_INET)
            elapsed_ms = (time.time() - start) * 1000
            results.append({"domain": domain, "time_ms": round(elapsed_ms, 1), "ok": True})
        except socket.gaierror:
            elapsed_ms = (time.time() - start) * 1000
            results.append({"domain": domain, "time_ms": round(elapsed_ms, 1), "ok": False})
    return results


# ── Progressive Trace ─────────────────────────────────────────────────────

def run_trace_cycle(target_name, target, cycle_num, stats, shutdown_check):
    """
    Full trace cycle for one target:
    1. Discover route (traceroute) — raw output saved
    2. N probe runs — each sends a packet hop-by-hop with increasing TTL
    3. Real-time display: each run = one line, each hop = one dot

    Returns: {ok_runs, fail_runs, faults: [{hop_num, host, zone}]}
    """
    ts = ts_now()
    ts_s = ts_short()

    # --- Route discovery ---
    route, raw_output = discover_route(target)
    log_raw_traceroute(ts, target_name, target, raw_output)
    log_event("traceroute", {
        "target_name": target_name, "target": target,
        "hops": route, "cycle": cycle_num,
    })

    if not route:
        print(f"  {YELLOW}Nie mozna odkryc trasy do {target}{RESET}")
        return {"ok_runs": 0, "fail_runs": RUNS_PER_TARGET, "faults": [], "rtt_stats": {}, "route": []}

    # Show discovered route
    route_hosts = [h["host"] for h in route if h["host"] != "???"]
    num_hops = len(route)
    known_hops = {h["hop_num"]: h["host"] for h in route}

    print(f"\n{DIM}[{ts_s}] {target_name} ({target}) "
          f"| {num_hops} hops | {RUNS_PER_TARGET} runs{RESET}")

    # Show hop legend
    legend_parts = []
    for h in route:
        zone = classify_hop(h["hop_num"])
        if h["host"] == "???":
            legend_parts.append(f"{DIM}*{RESET}")
        else:
            legend_parts.append(f"{h['host']}")
    print(f"  {DIM}route: {' > '.join(legend_parts)}{RESET}")

    # --- Probe runs ---
    ok_runs = 0
    fail_runs = 0
    faults = []  # list of {hop_num, host, zone}
    failed_runs_detail = []  # raw evidence for failed runs
    rtt_samples = []  # RTT from successful end-to-end runs

    # Per-hop counters for this cycle
    hop_reached = defaultdict(int)   # hop_num -> times packet passed through
    hop_failed = defaultdict(int)    # hop_num -> times packet died here
    hop_tested = defaultdict(int)    # hop_num -> times we tried

    for run_idx in range(RUNS_PER_TARGET):
        if shutdown_check():
            break

        run_num = run_idx + 1
        dots = ""
        run_result = None
        fail_hop = None
        run_raw_log = []  # raw output per hop for this run

        # Probe with increasing TTL
        for ttl in range(1, num_hops + 1):
            if shutdown_check():
                break

            expected_hop = known_hops.get(ttl, "???")

            # Skip ??? hops — just mark as passed
            if expected_hop == "???":
                dots += f"{DIM}-{RESET}"
                run_raw_log.append({"ttl": ttl, "hop": "???", "status": "skipped"})
                continue

            hop_tested[ttl] += 1

            # Show progress
            sys.stdout.write(
                f"\r  {DIM}#{run_num:<3}{RESET} {dots}{YELLOW}\u25cc{RESET}"
                f"{'.' * (num_hops - ttl)}   "
            )
            sys.stdout.flush()

            status, hop_ip, rtt, raw_output = ttl_ping(target, ttl)

            run_raw_log.append({
                "ttl": ttl, "hop": expected_hop,
                "status": status, "hop_ip": hop_ip,
                "rtt_ms": rtt, "raw": raw_output,
            })

            if status == "reached":
                # Packet reached the target — all hops passed
                dots += f"{GREEN}\u25cf{RESET}"
                hop_reached[ttl] += 1
                # Mark all prior non-??? hops as reached too
                for prev_ttl in range(1, ttl):
                    if known_hops.get(prev_ttl, "???") != "???":
                        pass  # already counted when they were ttl_exceeded
                run_result = "ok"
                if rtt is not None:
                    rtt_samples.append(rtt)
                rtt_str = f" {rtt:.0f}ms" if rtt else ""
                break

            elif status == "ttl_exceeded":
                # Packet passed through this hop
                dots += f"{GREEN}\u25cf{RESET}"
                hop_reached[ttl] += 1
                continue

            else:  # timeout
                # Packet died at this hop
                dots += f"{RED}\u25cf{RESET}"
                hop_failed[ttl] += 1
                run_result = "fail"
                fail_hop = ttl
                break

        # End of run — show final line
        if run_result == "ok":
            ok_runs += 1
            rtt_show = f" {rtt:.0f}ms" if rtt else ""
            sys.stdout.write(
                f"\r  {GREEN}#{run_num:<3}{RESET} {dots}"
                f"  {GREEN}\u2713{rtt_show}{RESET}          \n"
            )
        elif run_result == "fail":
            fail_runs += 1
            fh_host = known_hops.get(fail_hop, "???")
            fh_zone = classify_hop(fail_hop)
            faults.append({"hop_num": fail_hop, "host": fh_host, "zone": fh_zone})
            # Save raw evidence for this failed run
            failed_runs_detail.append({
                "run": run_num,
                "ts": ts_iso(),
                "fail_hop": fail_hop,
                "fail_host": fh_host,
                "fail_zone": fh_zone,
                "target": target_name,
                "hops_log": run_raw_log,
            })
            sys.stdout.write(
                f"\r  {RED}#{run_num:<3}{RESET} {dots}"
                f"  {RED}\u2717 hop {fail_hop} [{fh_zone}] {fh_host}{RESET}          \n"
            )
        else:
            # Interrupted or no result
            fail_runs += 1
            failed_runs_detail.append({
                "run": run_num,
                "ts": ts_iso(),
                "fail_hop": None,
                "fail_host": None,
                "fail_zone": "UNKNOWN",
                "target": target_name,
                "hops_log": run_raw_log,
            })
            sys.stdout.write(f"\r  {DIM}#{run_num:<3}{RESET} {dots}  {DIM}?{RESET}          \n")

        sys.stdout.flush()

        # Pause between runs
        if run_idx < RUNS_PER_TARGET - 1 and not shutdown_check():
            time.sleep(PAUSE_BETWEEN_RUNS)

    # --- RTT statistics ---
    rtt_stats = {}
    if rtt_samples:
        n = len(rtt_samples)
        rtt_avg = sum(rtt_samples) / n
        rtt_min = min(rtt_samples)
        rtt_max = max(rtt_samples)
        rtt_stddev = math.sqrt(sum((x - rtt_avg) ** 2 for x in rtt_samples) / n) if n > 1 else 0.0
        # Jitter = mean absolute difference between consecutive RTTs
        jitter = 0.0
        if n > 1:
            jitter = sum(abs(rtt_samples[i] - rtt_samples[i - 1]) for i in range(1, n)) / (n - 1)
        rtt_stats = {
            "min": round(rtt_min, 1),
            "max": round(rtt_max, 1),
            "avg": round(rtt_avg, 1),
            "stddev": round(rtt_stddev, 1),
            "jitter": round(jitter, 1),
            "samples": n,
        }

    # --- Cycle summary for this target ---
    total = ok_runs + fail_runs
    ok_pct = (ok_runs / total * 100) if total > 0 else 0

    if fail_runs == 0:
        color = GREEN
    elif ok_runs == 0:
        color = RED + BOLD
    else:
        color = YELLOW

    print(f"  {color}{ok_runs}/{total} OK ({ok_pct:.0f}%){RESET}", end="")
    if rtt_stats:
        print(f"  {DIM}avg {rtt_stats['avg']:.0f}ms "
              f"(jitter {rtt_stats['jitter']:.0f}ms){RESET}", end="")

    if faults:
        # Count faults per zone
        zone_faults = defaultdict(int)
        for f in faults:
            zone_faults[f["zone"]] += 1
        fault_parts = [f"{z}:{c}" for z, c in sorted(zone_faults.items())]
        print(f"  {RED}| faults: {' '.join(fault_parts)}{RESET}")
    else:
        print()

    # --- Log to CSV ---
    for hop_num in sorted(set(list(hop_reached.keys()) + list(hop_failed.keys()))):
        host = known_hops.get(hop_num, "???")
        zone = classify_hop(hop_num)
        reached = hop_reached.get(hop_num, 0)
        failed = hop_failed.get(hop_num, 0)
        csv_append(HOP_LOG, [
            ts, cycle_num, target_name, hop_num, host, zone,
            reached, failed, "",
        ])

    # --- Update global stats ---
    stats["total_runs"] += total
    stats["ok_runs"] += ok_runs
    stats["fail_runs"] += fail_runs

    for hop_num in hop_tested:
        host = known_hops.get(hop_num, "???")
        key = (hop_num, host)
        stats["hop_zones"][key] = classify_hop(hop_num)
        stats["hop_reached"][key] += hop_reached.get(hop_num, 0)
        stats["hop_failed"][key] += hop_failed.get(hop_num, 0)
        stats["hop_tested"][key] += hop_tested.get(hop_num, 0)

    for f in faults:
        stats["zone_faults"][f["zone"]] += 1

    # --- Log events ---
    log_event("trace_cycle", {
        "target_name": target_name, "target": target,
        "cycle": cycle_num, "runs": total,
        "ok": ok_runs, "fail": fail_runs,
        "faults": faults,
        "rtt_stats": rtt_stats,
        "hop_reached": dict(hop_reached),
        "hop_failed": dict(hop_failed),
        "failed_runs_detail": failed_runs_detail,
    })

    # --- Log incidents ---
    if fail_runs > 0:
        # Find most common fault zone
        zone_counts = defaultdict(int)
        for f in faults:
            zone_counts[f["zone"]] += 1
        if zone_counts:
            worst_zone = max(zone_counts, key=zone_counts.get)
            worst_fault = [f for f in faults if f["zone"] == worst_zone][0]
            csv_append(INCIDENTS_LOG, [
                ts, cycle_num, target_name, worst_zone,
                worst_fault["hop_num"], worst_fault["host"],
                f"{fail_runs}/{total} runs failed, "
                f"{zone_counts[worst_zone]}x at {worst_zone}",
            ])
            stats["total_incidents"] += 1
            stats["zone_incidents"][worst_zone] += 1

    return {"ok_runs": ok_runs, "fail_runs": fail_runs, "faults": faults, "rtt_stats": rtt_stats,
            "route": [h["host"] for h in route]}


# ── Display ───────────────────────────────────────────────────────────────

def print_drop_start(ts_s, fault_zone, detail, targets_count):
    w = 64
    bar = BG_RED + WHITE + BOLD
    print(f"\n{bar}{'':<{w}}{RESET}")
    print(f"{bar}{'[' + ts_s + ']  DROP DETECTED':<{w}}{RESET}")
    print(f"{bar}{'  Fault zone: ' + fault_zone:<{w}}{RESET}")
    if detail:
        print(f"{bar}{'  ' + detail:<{w}}{RESET}")
    print(f"{bar}{'  All ' + str(targets_count) + ' targets unreachable':<{w}}{RESET}")
    print(f"{bar}{'':<{w}}{RESET}")


def print_drop_continues(ts_s, elapsed, fault_zone):
    print(f"{RED}{BOLD}[{ts_s}] DROP CONTINUES -- {elapsed:.0f}s -- {fault_zone}{RESET}")


def print_drop_ended(ts_s, duration, fault_zone):
    print(f"\n{GREEN}{BOLD}[{ts_s}] DROP ENDED -- trwal {duration:.0f}s -- "
          f"fault: {fault_zone}{RESET}")


def print_session_summary(cycle, elapsed, stats, drop_time, uptime):
    total_runs = stats["total_runs"]
    ok_runs = stats["ok_runs"]
    fail_runs = stats["fail_runs"]
    ok_pct = (ok_runs / total_runs * 100) if total_runs > 0 else 100

    print(f"\n\n{'='*70}")
    print(f"{BOLD}  PODSUMOWANIE SESJI{RESET}")
    print(f"{'='*70}")
    print(f"  Cykle testowe:    {cycle}")
    print(f"  Czas trwania:     {elapsed/60:.1f} min")
    print(f"  Laczne probe'y:   {total_runs} ({ok_runs} OK, {fail_runs} fail, {ok_pct:.1f}% success)")
    print(f"  Incydenty:        {stats['total_incidents']}")
    print(f"  Przerwy (drop):   {stats['total_drops']} ({drop_time:.0f}s)")
    print(f"  Uptime:           {uptime:.1f}%")

    # --- Zone breakdown ---
    total_inc = stats["total_incidents"]
    if total_inc > 0:
        print(f"\n{BOLD}  Strefy usterek:{RESET}")
        print(f"  {'Strefa':<14} {'Ilosc':>7} {'Udzial':>8}")
        print(f"  {'-'*32}")
        for z in ("LOCAL", "ISP_EDGE", "ISP_CORE", "TRANSIT"):
            cnt = stats["zone_incidents"].get(z, 0)
            if cnt > 0:
                pct = cnt / total_inc * 100
                color = RED if z in ("ISP_EDGE", "ISP_CORE") else YELLOW
                print(f"  {color}{z:<14} {cnt:>7} {pct:>7.1f}%{RESET}")

    # --- Per-hop failure table ---
    hop_tested = stats["hop_tested"]
    if hop_tested:
        print(f"\n{BOLD}  Wyniki per hop (ile razy pakiet przeszedl / ile razy odpadl):{RESET}")
        print(f"  {'Hop':<5} {'Host':<22} {'Strefa':<12} "
              f"{'Przeszlo':>9} {'Odpadlo':>8} {'Testy':>6} {'% bled':>7}")
        print(f"  {'-'*72}")

        for key in sorted(hop_tested.keys(), key=lambda k: k[0]):
            hop_num, host = key
            zone = stats["hop_zones"].get(key, "?")
            reached = stats["hop_reached"].get(key, 0)
            failed = stats["hop_failed"].get(key, 0)
            tested = hop_tested[key]
            fail_pct = (failed / tested * 100) if tested > 0 else 0

            if fail_pct > LOSS_THRESHOLD:
                color = RED + BOLD
            elif fail_pct > 0:
                color = YELLOW
            else:
                color = GREEN

            print(f"  {color}{hop_num:<5} {host:<22} {zone:<12} "
                  f"{reached:>9} {failed:>8} {tested:>6} {fail_pct:>6.1f}%{RESET}")

    # --- Fault zone summary for AI ---
    zone_faults = stats["zone_faults"]
    if zone_faults:
        total_f = sum(zone_faults.values())
        print(f"\n{BOLD}  Rozbicie bledow per strefa (kazdy punkt = 1 run ktory odpadl):{RESET}")
        for z in ("LOCAL", "ISP_EDGE", "ISP_CORE", "TRANSIT"):
            cnt = zone_faults.get(z, 0)
            if cnt > 0:
                pct = cnt / total_f * 100
                bar_len = int(pct / 2)
                color = RED if z in ("ISP_EDGE", "ISP_CORE") else YELLOW
                print(f"  {color}{z:<14} {'#' * bar_len} {cnt} ({pct:.0f}%){RESET}")

    print(f"\n  Sesja:  {SESSION_DIR}")
    print(f"  Pliki:")
    print(f"    {CONNECTION_INFO.name:<24} konfiguracja polaczenia")
    print(f"    {EVENTS_LOG.name:<24} logi AI-friendly (JSONL)")
    print(f"    {TRACEROUTE_RAW.name:<24} surowe traceroute")
    print(f"    {HOP_LOG.name:<24} dane hop-by-hop (CSV)")
    print(f"    {INCIDENTS_LOG.name:<24} incydenty (CSV)")
    print(f"    {DROPS_LOG.name:<24} przerwy (CSV)")
    print(f"  Raport: python3 {sys.argv[0]} --report")
    print(f"{'='*70}\n")


# ── Report Generator ─────────────────────────────────────────────────────

def load_csv_rows(path, cutoff_str, ts_field="timestamp"):
    rows = []
    if not path.exists():
        return rows
    try:
        with open(path, "r") as f:
            for row in csv.DictReader(f):
                try:
                    if row.get(ts_field, "") >= cutoff_str:
                        rows.append(row)
                except Exception:
                    continue
    except Exception:
        pass
    return rows


def collect_session_data(cutoff_str):
    """Scan all session dirs under output/ and aggregate CSV data."""
    hop_rows = []
    incident_rows = []
    drop_rows = []
    speed_rows = []

    if not OUTPUT_DIR.exists():
        return hop_rows, incident_rows, drop_rows, speed_rows

    for session_dir in sorted(OUTPUT_DIR.iterdir()):
        if not session_dir.is_dir():
            continue
        hop_rows.extend(load_csv_rows(session_dir / "hop_log.csv", cutoff_str))
        incident_rows.extend(load_csv_rows(
            session_dir / "incidents_log.csv", cutoff_str))
        drop_rows.extend(load_csv_rows(
            session_dir / "drops_log.csv", cutoff_str, ts_field="drop_start"))
        speed_rows.extend(load_csv_rows(
            session_dir / "speed_log.csv", cutoff_str))

    return hop_rows, incident_rows, drop_rows, speed_rows


def generate_report(days=30):
    ensure_dirs()
    cutoff = datetime.now() - timedelta(days=days)
    cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

    hop_rows, incident_rows, drop_rows, speed_rows = collect_session_data(cutoff_str)

    # Count sessions
    session_count = 0
    if OUTPUT_DIR.exists():
        session_count = sum(1 for d in OUTPUT_DIR.iterdir() if d.is_dir())

    if not hop_rows and not incident_rows:
        print(f"{RED}Brak danych. Uruchom najpierw monitoring.{RESET}")
        if session_count > 0:
            print(f"{DIM}Znaleziono {session_count} sesji w {OUTPUT_DIR}, "
                  f"ale brak danych z ostatnich {days} dni.{RESET}")
        return

    all_ts = [r.get("timestamp", "") for r in hop_rows + incident_rows if r.get("timestamp")]
    first_ts = min(all_ts) if all_ts else "?"
    last_ts = max(all_ts) if all_ts else "?"
    total_cycles = len(set(r.get("cycle", "") for r in hop_rows if r.get("cycle")))

    zone_counts = defaultdict(int)
    for inc in incident_rows:
        zone_counts[inc.get("fault_zone", "UNKNOWN")] += 1
    total_incidents = sum(zone_counts.values())

    total_drop_seconds = sum(
        float(d.get("duration_seconds", 0)) for d in drop_rows
        if d.get("duration_seconds")
    )

    # Hop stats
    hop_agg = defaultdict(lambda: {"reached": 0, "failed": 0})
    for h in hop_rows:
        try:
            key = (h["target"], h["hop_num"], h.get("hop_host", "?"), h.get("hop_zone", "?"))
            hop_agg[key]["reached"] += int(h.get("reached", 0))
            hop_agg[key]["failed"] += int(h.get("failed_here", 0))
        except (ValueError, KeyError):
            continue

    report_ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # JSON
    report = {
        "generated": ts_now(),
        "period": {"from": first_ts, "to": last_ts, "days": days},
        "total_cycles": total_cycles,
        "total_incidents": total_incidents,
        "fault_zone_breakdown": dict(zone_counts),
        "total_drops": len(drop_rows),
        "total_downtime_seconds": round(total_drop_seconds, 1),
        "hop_stats": {str(k): v for k, v in hop_agg.items()},
        "incidents": [dict(i) for i in incident_rows[:200]],
        "drops": [dict(d) for d in drop_rows[:100]],
    }

    json_path = REPORT_DIR / f"report_{report_ts}.json"
    try:
        with open(json_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
    except OSError:
        pass

    # Markdown (Polish)
    md_path = REPORT_DIR / f"reklamacja_{report_ts}.md"
    drop_min = total_drop_seconds / 60
    isp_inc = zone_counts.get("ISP_EDGE", 0) + zone_counts.get("ISP_CORE", 0)
    local_inc = zone_counts.get("LOCAL", 0)

    md = []
    md.append("# Raport jakosci polaczenia internetowego\n")
    md.append(f"**Okres monitorowania:** {first_ts} -- {last_ts}\n")
    md.append("## Podsumowanie\n")
    md.append(f"Przeprowadzono **{total_cycles} cykli** diagnostycznych "
              f"z uzyciem `traceroute` + TTL-based `ping` do celow: "
              f"Google DNS 8.8.8.8, Cloudflare DNS 1.1.1.1, "
              f"google.com, cloudflare.com, amazon.com.\n")
    md.append(f"- **{total_incidents} incydentow** utraty pakietow\n")
    md.append(f"- **{len(drop_rows)} pelnych przerw**, laczny downtime: "
              f"**{drop_min:.1f} min**\n")

    md.append("\n## Analiza lokalizacji usterek\n")
    md.append("| Strefa | Incydenty | Udzial % |")
    md.append("|---|---|---|")
    for z in ("LOCAL", "ISP_EDGE", "ISP_CORE", "TRANSIT"):
        cnt = zone_counts.get(z, 0)
        pct = (cnt / total_incidents * 100) if total_incidents > 0 else 0
        md.append(f"| {z} | {cnt} | {pct:.1f}% |")
    md.append("")

    if total_incidents > 0 and isp_inc > local_inc:
        isp_pct = isp_inc / total_incidents * 100
        md.append(f"**Wniosek:** {isp_pct:.0f}% problemow wystapilo na infrastrukturze dostawcy. "
                  f"**Problem lezy po stronie ISP.**\n")

    md.append("\n## Dane hop-by-hop\n")
    md.append("| Cel | Hop | Strefa | Host | Przeszlo | Odpadlo | % bledow |")
    md.append("|---|---|---|---|---|---|---|")
    for key in sorted(hop_agg.keys(), key=lambda k: (k[0], int(k[1]))):
        tgt, hop_num, host, zone = key
        d = hop_agg[key]
        total = d["reached"] + d["failed"]
        pct = (d["failed"] / total * 100) if total > 0 else 0
        md.append(f"| {tgt} | {hop_num} | {zone} | {host} | "
                  f"{d['reached']} | {d['failed']} | {pct:.1f}% |")
    md.append("")

    if drop_rows:
        md.append("\n## Przerwy w lacznosci\n")
        md.append("| Poczatek | Koniec | Czas | Strefa |")
        md.append("|---|---|---|---|")
        for d in drop_rows[:50]:
            dur = float(d.get("duration_seconds", 0))
            md.append(f"| {d.get('drop_start','')} | {d.get('drop_end','')} "
                      f"| {dur:.0f}s | {d.get('fault_zone','')} |")
        md.append("")

    md.append("\n## Metodologia\n")
    md.append("Monitoring ciagly z uzyciem:\n")
    md.append("1. **traceroute** -- odkrywanie trasy do celu\n")
    md.append(f"2. **TTL-based ping** -- {RUNS_PER_TARGET} prob na cel na cykl, "
              f"kazda proba wysyla pakiet z rosnacym TTL (1,2,3,...) "
              f"aby sprawdzic kazdy hop na trasie. Pokazuje dokladnie "
              f"gdzie pakiet przechodzi a gdzie odpada.\n")
    md.append("3. **curl** -- periodyczne testy predkosci\n")
    md.append("\nKlasyfikacja: LOCAL (hop 1), ISP_EDGE (hop 2), "
              "ISP_CORE (hop 3-4), TRANSIT (hop 5+)\n")

    try:
        with open(md_path, "w") as f:
            f.write("\n".join(md))
    except OSError:
        pass

    print(f"\n{'='*65}")
    print(f"  RAPORT JAKOSCI POLACZENIA")
    print(f"{'='*65}")
    print(f"  Sesje:  {session_count} (w {OUTPUT_DIR})")
    print(f"  Okres:  {first_ts} -- {last_ts}")
    print(f"  Cykle:  {total_cycles} | Incydenty: {total_incidents}")
    print(f"  Przerwy: {len(drop_rows)} ({drop_min:.1f} min)")
    if total_incidents > 0:
        print(f"  ISP fault: {isp_inc}/{total_incidents} "
              f"({isp_inc/total_incidents*100:.0f}%)")
    print(f"\n  JSON: {json_path}")
    print(f"  Markdown: {md_path}")
    print(f"{'='*65}")
    return report


# ── Dashboard Generator ───────────────────────────────────────────────────

def load_sessions(days=30):
    """Load all session data for the dashboard."""
    cutoff = datetime.now() - timedelta(days=days)
    sessions = []

    if not OUTPUT_DIR.exists():
        return sessions

    for session_dir in sorted(OUTPUT_DIR.iterdir()):
        if not session_dir.is_dir():
            continue

        session = {
            "name": session_dir.name,
            "path": str(session_dir),
            "connection_info": None,
            "events": [],
            "cycles": [],
            "drops": [],
            "incidents": [],
        }

        # connection_info.json
        ci_path = session_dir / "connection_info.json"
        if ci_path.exists():
            try:
                with open(ci_path) as f:
                    session["connection_info"] = json.load(f)
            except Exception:
                pass

        # events.jsonl — parse into structured data
        ev_path = session_dir / "events.jsonl"
        if ev_path.exists():
            try:
                with open(ev_path) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            ev = json.loads(line)
                            ts = ev.get("ts", "")
                            if ts and ts >= cutoff.isoformat():
                                session["events"].append(ev)
                        except json.JSONDecodeError:
                            continue
            except Exception:
                pass

        # Extract cycles, drops, incidents from events
        for ev in session["events"]:
            t = ev.get("type")
            if t == "trace_cycle":
                session["cycles"].append(ev)
            elif t == "drop_start" or t == "drop_end":
                session["drops"].append(ev)
            elif t == "cycle_end":
                pass  # included in events

        # incidents CSV
        inc_path = session_dir / "incidents_log.csv"
        if inc_path.exists():
            try:
                with open(inc_path) as f:
                    for row in csv.DictReader(f):
                        session["incidents"].append(row)
            except Exception:
                pass

        if session["events"] or session["connection_info"]:
            sessions.append(session)

    return sessions


def _build_dashboard_data(days=30):
    """Build session summaries for the dashboard. Returns list of dicts or None."""
    sessions = load_sessions(days)
    if not sessions:
        return None

    session_summaries = []
    for s in sessions:
        ci = s["connection_info"] or {}
        net = ci.get("network", {})

        total_ok = 0
        total_fail = 0
        zone_faults = defaultdict(int)
        # Per-hop: keyed by "hop_num|ip" -> {zone, reached, failed, targets}
        failed_runs = []  # raw evidence for failed runs
        hop_detail = defaultdict(lambda: {
            "zone": "?", "reached": 0, "failed": 0, "targets": set()
        })
        timeline = []

        for ev in s["events"]:
            t = ev.get("type")
            if t == "trace_cycle":
                ok = ev.get("ok", 0)
                fail = ev.get("fail", 0)
                target_name = ev.get("target_name", "?")
                total_ok += ok
                total_fail += fail

                for f in ev.get("faults", []):
                    zone = f.get("zone", "?")
                    zone_faults[zone] += 1
                    key = f"{f.get('hop_num', '?')}|{f.get('host', '?')}"
                    hop_detail[key]["zone"] = zone
                    hop_detail[key]["failed"] += 1
                    hop_detail[key]["targets"].add(target_name)

                # Collect failed run raw evidence
                for frd in ev.get("failed_runs_detail", []):
                    failed_runs.append(frd)

                for hop_num_str, cnt in ev.get("hop_reached", {}).items():
                    # Find corresponding host from the route/faults
                    host = None
                    for f_item in ev.get("faults", []):
                        if str(f_item.get("hop_num")) == hop_num_str:
                            host = f_item.get("host")
                    # Also check hops from traceroute event in same cycle
                    if host:
                        key = f"{hop_num_str}|{host}"
                        hop_detail[key]["reached"] += cnt

                timeline.append({
                    "ts": ev.get("ts", ""),
                    "ok": ok, "fail": fail,
                    "target": target_name,
                })
            elif t == "drop_start":
                timeline.append({
                    "ts": ev.get("ts", ""), "event": "drop_start",
                    "zone": ev.get("fault_zone", ""),
                })
            elif t == "drop_end":
                timeline.append({
                    "ts": ev.get("ts", ""), "event": "drop_end",
                    "duration": ev.get("duration_seconds", 0),
                    "zone": ev.get("fault_zone", ""),
                })

        total_runs = total_ok + total_fail
        success_pct = (total_ok / total_runs * 100) if total_runs > 0 else 100

        # Convert hop_detail sets to lists for JSON
        hops_list = []
        for key, data in sorted(hop_detail.items(), key=lambda x: int(x[0].split("|")[0]) if x[0].split("|")[0].isdigit() else 99):
            parts = key.split("|", 1)
            hops_list.append({
                "hop_num": parts[0],
                "ip": parts[1] if len(parts) > 1 else "?",
                "zone": data["zone"],
                "reached": data["reached"],
                "failed": data["failed"],
                "targets": sorted(data["targets"]),
            })

        # Collect WiFi RSSI history from cycle_start events
        rssi_history = []
        for ev in s["events"]:
            if ev.get("type") == "cycle_start":
                ne = ev.get("network_env", {})
                rssi = ne.get("wifi_rssi_dbm")
                if rssi is not None:
                    rssi_history.append({
                        "ts": ev.get("ts", ""),
                        "rssi": rssi,
                        "noise": ne.get("wifi_noise_dbm"),
                        "tx_rate": ne.get("wifi_tx_rate"),
                    })

        summary = {
            "name": s["name"],
            "start": ci.get("session_start", s["name"]),
            "interface": net.get("interface", "?"),
            "interface_type": net.get("interface_type", "?"),
            "ip": net.get("ip", "?"),
            "gateway": net.get("gateway", "?"),
            "wifi_ssid": net.get("wifi_ssid"),
            "wifi_rssi": net.get("wifi_rssi_dbm"),
            "wifi_channel": net.get("wifi_channel"),
            "wifi_phy": net.get("wifi_phy_mode"),
            "rssi_history": rssi_history,
            "total_runs": total_runs,
            "ok_runs": total_ok,
            "fail_runs": total_fail,
            "success_pct": round(success_pct, 1),
            "zone_faults": dict(zone_faults),
            "incidents": len(s["incidents"]),
            "drops": [d for d in s["drops"] if d.get("type") == "drop_end"],
            "hops": hops_list,
            "timeline": timeline,
            "failed_runs": failed_runs,
        }
        session_summaries.append(summary)

    return session_summaries


def generate_dashboard(days=30):
    """Generate a self-contained HTML dashboard."""
    ensure_dirs()
    data = _build_dashboard_data(days)
    if not data:
        print(f"{RED}Brak danych. Uruchom najpierw monitoring.{RESET}")
        return

    payload = json.dumps({
        "sessions": data,
        "monitor": {"running": False},
    }, indent=2, default=str)
    html = _build_dashboard_html(payload, days)

    out_path = REPORT_DIR / "dashboard.html"
    try:
        with open(out_path, "w") as f:
            f.write(html)
    except OSError as e:
        print(f"{RED}Cannot write dashboard: {e}{RESET}")
        return

    print(f"\n{GREEN}Dashboard: {out_path}{RESET}")
    import webbrowser
    webbrowser.open(f"file://{out_path}")


def _check_monitor_status():
    """Check if monitoring is currently running. Returns dict with status info."""
    lock_path = DATA_DIR / "monitor.lock"
    if not lock_path.exists():
        return {"running": False}

    try:
        pid = int(lock_path.read_text().strip())
        if _pid_alive(pid):
            # Find which session dir is active (most recent)
            active_session = None
            if OUTPUT_DIR.exists():
                dirs = sorted(
                    (d for d in OUTPUT_DIR.iterdir() if d.is_dir()),
                    reverse=True
                )
                if dirs:
                    active_session = dirs[0].name
            return {
                "running": True,
                "pid": pid,
                "session": active_session,
            }
        else:
            return {"running": False}
    except (ValueError, OSError):
        return {"running": False}


def live_dashboard(days=30, port=8077):
    """Run a live dashboard with auto-refresh via a local HTTP server."""
    from http.server import HTTPServer, BaseHTTPRequestHandler
    ensure_dirs()

    # Check and show monitor status at startup
    status = _check_monitor_status()
    if status["running"]:
        print(f"  {GREEN}Monitoring aktywny{RESET} (PID {status['pid']}"
              f"{', sesja: ' + status['session'] if status.get('session') else ''})")
    else:
        print(f"  {YELLOW}Monitoring nieaktywny{RESET} — uruchom w innym terminalu")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/data":
                data = _build_dashboard_data(days)
                status = _check_monitor_status()
                payload = json.dumps({
                    "sessions": data or [],
                    "monitor": status,
                }, default=str)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(payload.encode())
            elif self.path == "/" or self.path == "/index.html":
                data = _build_dashboard_data(days)
                status = _check_monitor_status()
                init_payload = json.dumps({
                    "sessions": data or [],
                    "monitor": status,
                }, indent=2, default=str)
                html = _build_dashboard_html(init_payload, days, live=True)
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(html.encode())
            else:
                self.send_error(404)

        def log_message(self, format, *args):
            pass  # suppress request logs

    url = f"http://localhost:{port}"
    print(f"\n{BOLD}Net Monitor — Live Dashboard{RESET}")
    print(f"{GREEN}  {url}{RESET}")
    print(f"{DIM}  Auto-refresh co 5s | Ctrl+C aby zatrzymac{RESET}\n")

    import webbrowser
    webbrowser.open(url)

    try:
        server = HTTPServer(("", port), Handler)
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{DIM}Dashboard zatrzymany.{RESET}")
    except OSError as e:
        if "Address already in use" in str(e):
            print(f"{RED}Port {port} jest zajety. Uzyj --port N{RESET}")
        else:
            raise


def _build_dashboard_html(data_json, days, live=False):
    live_js = ""
    if live:
        live_js = """
// ── Live auto-refresh ──
(function() {
  var POLL_SEC = 5;
  var countdown = POLL_SEC;
  var polling = false;

  var btn = document.getElementById('live-btn');
  if (!btn) return;
  btn.onclick = function() { countdown = 0; doRefresh(); };

  var lastDataHash = JSON.stringify(DATA);

  btn.style.display = 'inline-block';

  function updateBtn(text, color) {
    btn.style.color = color;
    btn.style.borderColor = color;
    btn.innerHTML = text;
  }

  async function doRefresh() {
    if (polling) return;
    polling = true;
    updateBtn('&#8635; refreshing...', 'var(--yellow)');
    try {
      var resp = await fetch('/data');
      if (!resp.ok) { polling = false; return; }
      var payload = await resp.json();
      var sessions = payload.sessions || payload;
      MONITOR = payload.monitor || {};
      var newHash = JSON.stringify(sessions);
      if (newHash !== lastDataHash) {
        lastDataHash = newHash;
        DATA.length = 0;
        sessions.forEach(function(d) { DATA.push(d); });
        var prevIdx = activeIdx;
        renderSidebar();
        if (prevIdx >= 0 && prevIdx < DATA.length) {
          selectSession(prevIdx);
        } else if (DATA.length) {
          selectSession(DATA.length - 1);
        }
      }
      renderStatusBar();
      countdown = POLL_SEC;
    } catch(e) {
      updateBtn('&#9679; OFFLINE', 'var(--red)');
      countdown = POLL_SEC;
    }
    polling = false;
  }

  setInterval(function() {
    if (polling) return;
    countdown--;
    if (countdown <= 0) {
      doRefresh();
    } else {
      updateBtn('&#9679; LIVE ' + countdown + 's', 'var(--green)');
    }
  }, 1000);
})();
"""
    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Net Monitor Dashboard</title>
<style>
:root {{
  --bg: #0d1117; --bg2: #161b22; --bg3: #21262d;
  --fg: #c9d1d9; --fg2: #8b949e; --fg3: #484f58;
  --green: #3fb950; --red: #f85149; --yellow: #d29922;
  --blue: #58a6ff; --purple: #bc8cff; --orange: #db6d28;
  --border: #30363d;
}}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace;
  background: var(--bg); color: var(--fg); }}
.layout {{ display: flex; height: 100vh; }}
.sidebar {{
  width: 280px; min-width: 280px; background: var(--bg2);
  border-right: 1px solid var(--border); overflow-y: auto;
  padding: 16px 0;
}}
.sidebar h1 {{ font-size: 1em; color: var(--blue); padding: 0 16px 12px; }}
.session-btn {{
  display: block; width: 100%; padding: 10px 16px;
  background: none; border: none; border-left: 3px solid transparent;
  color: var(--fg2); text-align: left; cursor: pointer;
  font-family: inherit; font-size: 0.82em; transition: all 0.15s;
}}
.session-btn:hover {{ background: var(--bg3); color: var(--fg); }}
.session-btn.active {{
  background: var(--bg3); color: var(--fg);
  border-left-color: var(--blue);
}}
.session-btn .s-date {{ font-weight: 600; }}
.session-btn .s-meta {{ font-size: 0.85em; margin-top: 2px; }}
.session-btn .s-badge {{
  display: inline-block; padding: 1px 6px; border-radius: 8px;
  font-size: 0.8em; font-weight: 600;
}}
.s-ok {{ background: rgba(63,185,80,0.15); color: var(--green); }}
.s-warn {{ background: rgba(210,153,34,0.15); color: var(--yellow); }}
.s-bad {{ background: rgba(248,81,73,0.15); color: var(--red); }}
.main {{ flex: 1; overflow-y: auto; padding: 24px; }}
.card {{
  background: var(--bg2); border: 1px solid var(--border);
  border-radius: 8px; padding: 20px; margin-bottom: 16px;
}}
.card h2 {{ font-size: 1em; color: var(--fg2); margin-bottom: 12px; }}
.grid {{ display: grid; gap: 16px; }}
.grid-2 {{ grid-template-columns: 1fr 1fr; }}
.grid-3 {{ grid-template-columns: 1fr 1fr 1fr; }}
.grid-4 {{ grid-template-columns: repeat(4, 1fr); }}
@media(max-width:900px) {{ .grid-2,.grid-3,.grid-4 {{ grid-template-columns:1fr; }} }}
.metric {{ text-align: center; padding: 12px; }}
.metric .num {{ font-size: 1.8em; font-weight: bold; line-height: 1.2; }}
.metric .lbl {{ font-size: 0.78em; color: var(--fg2); }}
table {{ width: 100%; border-collapse: collapse; font-size: 0.85em; }}
th {{ text-align: left; padding: 8px 10px; border-bottom: 2px solid var(--border);
  color: var(--fg2); font-weight: 600; }}
td {{ padding: 6px 10px; border-bottom: 1px solid var(--border); }}
tr:hover td {{ background: var(--bg3); }}
.bar-bg {{ width: 100%; height: 6px; background: var(--bg3); border-radius: 3px; }}
.bar-fill {{ height: 100%; border-radius: 3px; }}
.pie-row {{ display: flex; align-items: center; gap: 20px; }}
.pie-legend {{ font-size: 0.85em; }}
.pie-legend div {{ margin: 4px 0; display: flex; align-items: center; gap: 8px; }}
.pie-dot {{ width: 10px; height: 10px; border-radius: 50%; display: inline-block; }}
.conn-grid {{
  display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
  gap: 8px;
}}
.conn-cell {{ background: var(--bg3); padding: 8px 12px; border-radius: 6px; }}
.conn-cell .cl {{ font-size: 0.72em; color: var(--fg2); }}
.conn-cell .cv {{ font-size: 0.88em; font-weight: 500; }}
.timeline {{ display:flex; gap:1px; height:40px; align-items:flex-end; margin:8px 0; }}
.tbar {{
  min-width:3px; flex:1; border-radius:2px 2px 0 0; max-width:10px;
  cursor:pointer; position:relative;
}}
.tbar:hover::after {{
  content:attr(data-tip); position:absolute; bottom:105%;
  left:50%; transform:translateX(-50%); background:#000; color:var(--fg);
  padding:4px 8px; border-radius:4px; font-size:0.72em; white-space:nowrap; z-index:10;
  pointer-events:none;
}}
.empty {{ color: var(--fg3); text-align: center; padding: 40px; }}
.hop-ip {{ font-family: monospace; color: var(--blue); }}
.hop-zone {{ font-size: 0.8em; padding: 2px 6px; border-radius: 4px; }}
.zone-local {{ background: rgba(63,185,80,0.12); color: var(--green); }}
.zone-isp {{ background: rgba(248,81,73,0.12); color: var(--red); }}
.zone-transit {{ background: rgba(139,148,158,0.12); color: var(--fg2); }}
.failed-run {{
  background: var(--bg3); border: 1px solid var(--border); border-radius: 6px;
  margin: 6px 0; overflow: hidden;
}}
.failed-run-header {{
  padding: 8px 12px; cursor: pointer; display: flex; justify-content: space-between;
  align-items: center; font-size: 0.85em; user-select: none;
}}
.failed-run-header:hover {{ background: rgba(248,81,73,0.06); }}
.failed-run-body {{
  display: none; padding: 0 12px 10px; font-size: 0.78em;
}}
.failed-run-body.open {{ display: block; }}
.raw-log {{
  background: var(--bg); border: 1px solid var(--border); border-radius: 4px;
  padding: 8px 10px; margin: 4px 0; font-family: monospace;
  white-space: pre-wrap; word-break: break-all; font-size: 0.9em;
  color: var(--fg2); max-height: 200px; overflow-y: auto;
}}
.hop-badge {{
  display: inline-block; padding: 1px 6px; border-radius: 4px;
  font-size: 0.82em; margin: 0 2px;
}}
.hop-ok {{ background: rgba(63,185,80,0.12); color: var(--green); }}
.hop-fail {{ background: rgba(248,81,73,0.15); color: var(--red); font-weight: 600; }}
.hop-skip {{ background: rgba(139,148,158,0.12); color: var(--fg3); }}
.rssi-chart {{ height: 60px; display: flex; align-items: flex-end; gap: 1px; margin: 8px 0; }}
.rssi-bar {{
  flex: 1; min-width: 2px; max-width: 6px; border-radius: 2px 2px 0 0;
  cursor: pointer; position: relative;
}}
.rssi-bar:hover::after {{
  content:attr(data-tip); position:absolute; bottom:105%;
  left:50%; transform:translateX(-50%); background:#000; color:var(--fg);
  padding:4px 8px; border-radius:4px; font-size:0.72em; white-space:nowrap; z-index:10;
}}
.toggle-arrow {{ transition: transform 0.2s; display: inline-block; }}
.toggle-arrow.open {{ transform: rotate(90deg); }}
</style>
</head>
<body>
<div class="layout">

<div class="sidebar" id="sidebar">
  <h1>Net Monitor</h1>
  <div style="display:flex;gap:6px;margin:-8px 0 10px 0">
    <button id="lang-btn" onclick="toggleLang()" style="font-size:0.7em;background:var(--bg3);color:var(--fg2);border:1px solid var(--fg3);border-radius:3px;padding:2px 8px;cursor:pointer"></button>
    <button id="live-btn" title="Click to refresh" style="font-size:0.7em;background:var(--bg3);color:var(--green);border:1px solid var(--green);border-radius:3px;padding:2px 8px;cursor:pointer;display:none">&#9679; LIVE</button>
  </div>
  <div id="session-list"></div>
</div>

<div class="main" id="main">
  <div class="empty" id="empty-msg"></div>
</div>

</div>

<div id="status-bar" style="display:none;position:fixed;bottom:0;left:0;right:0;padding:6px 16px;font-size:0.78em;font-family:monospace;z-index:100;border-top:1px solid var(--border)"></div>

<script>
const _INIT = {data_json};
const DATA = _INIT.sessions || _INIT;
let MONITOR = _INIT.monitor || {{}};
let activeIdx = -1;

// ── i18n ──
const I18N = {{
  en: {{
    select_session: 'Select a session from the list',
    session: 'Session', total_runs: 'total runs',
    fault_analysis: 'Fault Analysis', faults_by_zone: 'Faults by Zone',
    faults_by_hop: 'Faults by Hop (IP)', failures_by_hop: 'Failures by Hop / IP',
    no_failures: 'No failures', wifi_over_time: 'WiFi Signal (RSSI) over time',
    drops: 'Connectivity Drops', failed_evidence: 'Failed Runs \u2014 Evidence',
    evidence_hint: 'Each entry contains raw ping logs per hop. Click to expand.',
    no_data: 'No data', hop: 'Hop', zone: 'Zone', failures: 'Failures',
    fail_pct: 'Fail %', time: 'Time', duration: 'Duration',
    raw_logs: 'Raw ping logs per hop:', samples: 'Samples',
    monitoring_active: 'Monitoring active', monitoring_inactive: 'Monitoring inactive',
    slow: 'slow!', timeline: 'Timeline',
  }},
  pl: {{
    select_session: 'Wybierz sesj\u0119 z listy',
    session: 'Sesja', total_runs: 'pr\u00f3b \u0142\u0105cznie',
    fault_analysis: 'Analiza b\u0142\u0119d\u00f3w', faults_by_zone: 'B\u0142\u0119dy per strefa',
    faults_by_hop: 'B\u0142\u0119dy per hop (IP)', failures_by_hop: 'Awarie per hop / IP',
    no_failures: 'Brak awarii', wifi_over_time: 'WiFi Signal (RSSI) w czasie',
    drops: 'Przerwy w \u0142\u0105czno\u015bci', failed_evidence: 'Sfailowane runy \u2014 dowody',
    evidence_hint: 'Ka\u017cdy wpis zawiera surowe logi z pinga per hop. Kliknij aby rozwina\u0107.',
    no_data: 'Brak danych', hop: 'Hop', zone: 'Strefa', failures: 'Awarie',
    fail_pct: '% b\u0142\u0119d\u00f3w', time: 'Czas', duration: 'Czas trwania',
    raw_logs: 'Surowe logi ping per hop:', samples: 'Punkt\u00f3w',
    monitoring_active: 'Monitoring aktywny', monitoring_inactive: 'Monitoring nieaktywny',
    slow: 'powolny!', timeline: 'Timeline',
  }}
}};

let LANG = (navigator.language || 'en').startsWith('pl') ? 'pl' : 'en';
function t(key) {{ return (I18N[LANG] || I18N.en)[key] || key; }}

const ZONE_COLORS = {{
  LOCAL: '#3fb950', ISP_EDGE: '#f85149', ISP_CORE: '#db6d28',
  TRANSIT: '#8b949e', UNKNOWN: '#484f58'
}};

function zc(zone) {{ return ZONE_COLORS[zone] || '#484f58'; }}

// ── Pie chart (canvas) ──
function drawPie(canvasId, slices) {{
  const el = document.getElementById(canvasId);
  if (!el) return;
  const ctx = el.getContext('2d');
  const w = el.width, h = el.height, r = Math.min(w,h)/2 - 4;
  const cx = w/2, cy = h/2;
  const total = slices.reduce((s,x) => s + x.value, 0);
  if (total === 0) return;
  let angle = -Math.PI/2;
  slices.forEach(s => {{
    const sweep = (s.value/total) * Math.PI * 2;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, r, angle, angle + sweep);
    ctx.closePath();
    ctx.fillStyle = s.color;
    ctx.fill();
    angle += sweep;
  }});
  // Center hole (donut)
  ctx.beginPath();
  ctx.arc(cx, cy, r * 0.55, 0, Math.PI * 2);
  ctx.fillStyle = '#161b22';
  ctx.fill();
  // Center text
  ctx.fillStyle = '#c9d1d9';
  ctx.font = 'bold 14px monospace';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  const mainSlice = slices.reduce((a,b) => a.value > b.value ? a : b);
  ctx.fillText(Math.round(mainSlice.value/total*100) + '%', cx, cy - 6);
  ctx.font = '10px monospace';
  ctx.fillStyle = '#8b949e';
  ctx.fillText(mainSlice.label, cx, cy + 10);
}}

// ── Session list ──
function renderSidebar() {{
  const list = document.getElementById('session-list');
  list.innerHTML = '';
  DATA.forEach((s, i) => {{
    const bc = s.success_pct >= 95 ? 's-ok' : s.success_pct >= 80 ? 's-warn' : 's-bad';
    const d = s.start || s.name;
    const conn = s.wifi_ssid ? s.wifi_ssid + ' ' + (s.wifi_rssi||'') + 'dBm'
      : s.interface_type === 'ethernet' ? 'Ethernet' : s.interface_type;
    const btn = document.createElement('button');
    btn.className = 'session-btn';
    btn.innerHTML = `<div class="s-date">${{d}}</div>
      <div class="s-meta">${{conn}} &nbsp;<span class="s-badge ${{bc}}">${{s.success_pct}}%</span>
      ${{s.fail_runs ? ' <span class="s-badge s-bad">'+s.fail_runs+'F</span>' : ''}}</div>`;
    btn.onclick = () => selectSession(i);
    list.appendChild(btn);
  }});
}}

function selectSession(idx) {{
  activeIdx = idx;
  document.querySelectorAll('.session-btn').forEach((b,i) => {{
    b.classList.toggle('active', i === idx);
  }});
  renderSession(DATA[idx]);
}}

// ── Main session view ──
function renderSession(s) {{
  const main = document.getElementById('main');
  const pieId1 = 'pie-zones-' + s.name;
  const pieId2 = 'pie-hops-' + s.name;

  // Aggregate hop failure data
  const failHops = (s.hops || []).filter(h => h.failed > 0);
  const totalFaults = failHops.reduce((a,h) => a + h.failed, 0);

  main.innerHTML = `
    <div class="card">
      <h2>${{t('session')}}: ${{s.start || s.name}}</h2>
      <div class="conn-grid">
        <div class="conn-cell"><div class="cl">Interface</div><div class="cv">${{s.interface}} (${{s.interface_type}})</div></div>
        <div class="conn-cell"><div class="cl">IP</div><div class="cv">${{s.ip}}</div></div>
        <div class="conn-cell"><div class="cl">Gateway</div><div class="cv">${{s.gateway}}</div></div>
        ${{s.wifi_ssid ? `
          <div class="conn-cell"><div class="cl">SSID</div><div class="cv">${{s.wifi_ssid}}</div></div>
          <div class="conn-cell"><div class="cl">Signal</div><div class="cv">${{s.wifi_rssi||'?'}} dBm</div></div>
          <div class="conn-cell"><div class="cl">Channel</div><div class="cv">${{s.wifi_channel||'?'}}</div></div>
          <div class="conn-cell"><div class="cl">PHY</div><div class="cv">${{s.wifi_phy||'?'}}</div></div>
        ` : ''}}
      </div>
    </div>

    <div class="card">
      <div class="grid grid-4">
        <div class="metric"><div class="num">${{s.total_runs}}</div><div class="lbl">${{t('total_runs')}}</div></div>
        <div class="metric"><div class="num" style="color:var(--green)">${{s.ok_runs}}</div><div class="lbl">OK</div></div>
        <div class="metric"><div class="num" style="color:var(--red)">${{s.fail_runs}}</div><div class="lbl">FAIL</div></div>
        <div class="metric"><div class="num" style="color:${{s.success_pct>=95?'var(--green)':s.success_pct>=80?'var(--yellow)':'var(--red)'}}">${{s.success_pct}}%</div><div class="lbl">success rate</div></div>
      </div>
    </div>

    <div class="card">
      <h2>${{t('timeline')}}</h2>
      ${{renderTimeline(s.timeline)}}
    </div>

    <div class="card">
      <h2>${{t('fault_analysis')}}</h2>
      <div class="grid grid-2">
        <div>
          <h2 style="margin-top:0">${{t('faults_by_zone')}}</h2>
          <div class="pie-row">
            <canvas id="${{pieId1}}" width="140" height="140"></canvas>
            <div class="pie-legend" id="legend-${{pieId1}}"></div>
          </div>
        </div>
        <div>
          <h2 style="margin-top:0">${{t('faults_by_hop')}}</h2>
          <div class="pie-row">
            <canvas id="${{pieId2}}" width="140" height="140"></canvas>
            <div class="pie-legend" id="legend-${{pieId2}}"></div>
          </div>
        </div>
      </div>
    </div>

    <div class="card">
      <h2>${{t('failures_by_hop')}}</h2>
      ${{failHops.length ? renderHopTable(s.hops, s.total_runs) : '<div style="color:var(--green)">' + t('no_failures') + '</div>'}}
    </div>

    ${{s.rssi_history && s.rssi_history.length > 1 ? `<div class="card">
      <h2>${{t('wifi_over_time')}}</h2>
      ${{renderRssiChart(s.rssi_history)}}
    </div>` : ''}}

    ${{s.drops.length ? `<div class="card">
      <h2>${{t('drops')}} (${{s.drops.length}})</h2>
      ${{renderDrops(s.drops)}}
    </div>` : ''}}

    ${{(s.failed_runs && s.failed_runs.length) ? `<div class="card">
      <h2>${{t('failed_evidence')}} (${{s.failed_runs.length}})</h2>
      <div style="font-size:0.82em;color:var(--fg2);margin-bottom:10px">
        ${{t('evidence_hint')}}
      </div>
      ${{renderFailedRuns(s.failed_runs)}}
    </div>` : ''}}
  `;

  // Draw pie charts after DOM is ready
  setTimeout(() => {{
    // Zone pie
    const zones = Object.entries(s.zone_faults).filter(([z,c]) => c > 0);
    if (zones.length) {{
      const slices = zones.map(([z,c]) => ({{label:z, value:c, color:zc(z)}}));
      drawPie(pieId1, slices);
      const leg = document.getElementById('legend-' + pieId1);
      if (leg) {{
        const total = zones.reduce((a,x) => a+x[1], 0);
        leg.innerHTML = zones.map(([z,c]) =>
          `<div><span class="pie-dot" style="background:${{zc(z)}}"></span>
          ${{z}}: ${{c}} (${{(c/total*100).toFixed(0)}}%)</div>`
        ).join('');
      }}
    }}

    // Hop pie
    if (failHops.length) {{
      const hopSlices = failHops
        .sort((a,b) => b.failed - a.failed)
        .slice(0, 8)
        .map((h, i) => {{
          const colors = ['#f85149','#db6d28','#d29922','#bc8cff','#58a6ff','#3fb950','#8b949e','#484f58'];
          return {{label: 'hop'+h.hop_num+' '+h.ip, value: h.failed, color: colors[i%colors.length]}};
        }});
      drawPie(pieId2, hopSlices);
      const leg2 = document.getElementById('legend-' + pieId2);
      if (leg2) {{
        leg2.innerHTML = hopSlices.map(sl =>
          `<div><span class="pie-dot" style="background:${{sl.color}}"></span>
          ${{sl.label}}: ${{sl.value}}</div>`
        ).join('');
      }}
    }}
  }}, 50);
}}

function renderTimeline(timeline) {{
  if (!timeline || !timeline.length) return '<div style="color:var(--fg3)">' + t('no_data') + '</div>';
  let html = '<div class="timeline">';
  timeline.forEach(t => {{
    if (t.event === 'drop_start') {{
      html += `<div class="tbar" style="height:100%;background:var(--red);opacity:0.3"
        data-tip="DROP START ${{t.zone}}"></div>`;
    }} else if (t.event === 'drop_end') {{
      html += `<div class="tbar" style="height:100%;background:var(--red)"
        data-tip="DROP ${{t.duration}}s ${{t.zone}}"></div>`;
    }} else {{
      const total = (t.ok||0) + (t.fail||0);
      const pct = total > 0 ? t.ok/total : 1;
      const h = Math.max(20, pct * 100);
      const c = pct >= 1 ? 'var(--green)' : pct >= 0.8 ? 'var(--yellow)' : 'var(--red)';
      const time = t.ts ? t.ts.split('T')[1]?.substring(0,8) || '' : '';
      html += `<div class="tbar" style="height:${{h}}%;background:${{c}}"
        data-tip="${{time}} ${{t.target}} ${{t.ok}}/${{total}} OK"></div>`;
    }}
  }});
  html += '</div>';
  return html;
}}

function renderHopTable(hops, totalRuns) {{
  let html = '<table><tr><th>' + t('hop') + '</th><th>IP</th><th>' + t('zone') + '</th><th>' + t('failures') + '</th><th>Targets</th><th>' + t('fail_pct') + '</th><th></th></tr>';
  hops.filter(h => h.failed > 0).sort((a,b) => b.failed - a.failed).forEach(h => {{
    const total = h.reached + h.failed;
    const pct = total > 0 ? (h.failed/total*100).toFixed(1) : '0';
    const pctNum = parseFloat(pct);
    const zclass = (h.zone==='LOCAL') ? 'zone-local'
      : (h.zone==='ISP_EDGE'||h.zone==='ISP_CORE') ? 'zone-isp' : 'zone-transit';
    const barColor = pctNum > 20 ? 'var(--red)' : pctNum > 5 ? 'var(--yellow)' : 'var(--green)';
    html += `<tr>
      <td><b>hop ${{h.hop_num}}</b></td>
      <td class="hop-ip">${{h.ip}}</td>
      <td><span class="hop-zone ${{zclass}}">${{h.zone}}</span></td>
      <td style="color:var(--red);font-weight:600">${{h.failed}}</td>
      <td style="font-size:0.8em;color:var(--fg2)">${{h.targets.join(', ')}}</td>
      <td>${{pct}}%</td>
      <td style="width:100px"><div class="bar-bg"><div class="bar-fill" style="width:${{Math.min(100,pctNum)}}%;background:${{barColor}}"></div></div></td>
    </tr>`;
  }});
  html += '</table>';
  return html;
}}

function renderDrops(drops) {{
  let html = '<table><tr><th>' + t('time') + '</th><th>' + t('duration') + '</th><th>' + t('zone') + '</th></tr>';
  drops.forEach(d => {{
    html += `<tr><td>${{d.ts||''}}</td><td style="font-weight:600;color:var(--red)">${{d.duration||0}}s</td>
      <td style="color:${{zc(d.zone)}}">${{d.zone||'?'}}</td></tr>`;
  }});
  html += '</table>';
  return html;
}}

function renderRssiChart(history) {{
  if (!history || history.length < 2) return '';
  const vals = history.map(h => h.rssi);
  const minR = Math.min(...vals);
  const maxR = Math.max(...vals);
  const range = Math.max(maxR - minR, 10);
  const avg = (vals.reduce((a,b)=>a+b,0)/vals.length).toFixed(1);
  const mn = Math.min(...vals);
  const mx = Math.max(...vals);

  let html = `<div style="font-size:0.82em;color:var(--fg2);margin-bottom:4px">` +
    `Min: <b>${{mn}}</b> dBm | Max: <b>${{mx}}</b> dBm | Avg: <b>${{avg}}</b> dBm | ${{t('samples')}}: ${{vals.length}}</div>`;
  html += '<div class="rssi-chart">';
  history.forEach(h => {{
    const pct = Math.max(10, ((h.rssi - minR + 5) / (range + 10)) * 100);
    const c = h.rssi >= -50 ? 'var(--green)' : h.rssi >= -65 ? 'var(--green)' :
      h.rssi >= -75 ? 'var(--yellow)' : 'var(--red)';
    const time = h.ts ? h.ts.split('T')[1]?.substring(0,8) || '' : '';
    html += `<div class="rssi-bar" style="height:${{pct}}%;background:${{c}}"
      data-tip="${{time}} ${{h.rssi}}dBm"></div>`;
  }});
  html += '</div>';
  return html;
}}

function renderFailedRuns(runs) {{
  if (!runs || !runs.length) return '';
  let html = '';
  runs.forEach((r, idx) => {{
    const time = r.ts ? r.ts.split('T')[1]?.substring(0,8) || r.ts : '';
    const hopInfo = r.fail_hop ? `hop ${{r.fail_hop}} [${{r.fail_zone}}] ${{r.fail_host}}` : 'unknown';
    const zclass = (r.fail_zone==='LOCAL') ? 'zone-local'
      : (r.fail_zone==='ISP_EDGE'||r.fail_zone==='ISP_CORE') ? 'zone-isp' : 'zone-transit';

    html += `<div class="failed-run">
      <div class="failed-run-header" onclick="this.querySelector('.toggle-arrow').classList.toggle('open');this.nextElementSibling.classList.toggle('open')">
        <div>
          <span class="toggle-arrow">&#9654;</span>
          <b style="color:var(--red)">Run #${{r.run}}</b>
          <span style="color:var(--fg2);margin:0 8px">${{time}}</span>
          <span style="color:var(--fg2)">${{r.target}}</span>
          <span style="margin-left:8px">&#10007; ${{hopInfo}}</span>
          <span class="hop-zone ${{zclass}}" style="margin-left:6px">${{r.fail_zone||'?'}}</span>
        </div>
      </div>
      <div class="failed-run-body">`;

    // Show hop-by-hop badges
    html += '<div style="margin-bottom:8px">';
    (r.hops_log || []).forEach(h => {{
      if (h.status === 'skipped') {{
        html += `<span class="hop-badge hop-skip">${{h.ttl}}:???</span>`;
      }} else if (h.status === 'timeout') {{
        html += `<span class="hop-badge hop-fail">${{h.ttl}}:${{h.hop}} TIMEOUT</span>`;
      }} else if (h.status === 'reached') {{
        html += `<span class="hop-badge hop-ok">${{h.ttl}}:&#10003; ${{h.rtt_ms ? h.rtt_ms.toFixed(0)+'ms' : ''}}</span>`;
      }} else {{
        html += `<span class="hop-badge hop-ok">${{h.ttl}}:${{h.hop_ip||h.hop}}</span>`;
      }}
    }});
    html += '</div>';

    // Show raw logs per hop
    html += '<div style="font-size:0.82em;color:var(--fg2);margin-bottom:4px">' + t('raw_logs') + '</div>';
    (r.hops_log || []).forEach(h => {{
      if (h.status !== 'skipped' && h.raw) {{
        const statusColor = h.status === 'timeout' ? 'var(--red)' : 'var(--green)';
        html += `<div style="margin:2px 0;font-size:0.85em">
          <b style="color:${{statusColor}}">TTL ${{h.ttl}}</b> (${{h.hop}}) — ${{h.status}}
        </div>
        <div class="raw-log">${{escHtml(h.raw)}}</div>`;
      }}
    }});

    html += '</div></div>';
  }});
  return html;
}}

function escHtml(s) {{
  if (!s) return '';
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}}

// ── Monitor status bar ──
function renderStatusBar() {{
  var bar = document.getElementById('status-bar');
  if (!bar) return;
  if (MONITOR && MONITOR.running) {{
    bar.style.display = 'block';
    bar.style.background = '#0d1117';
    bar.style.color = '#3fb950';
    bar.innerHTML = '\u25cf ' + t('monitoring_active') + ' &mdash; PID ' + MONITOR.pid
      + (MONITOR.session ? ' | session: ' + MONITOR.session : '');
  }} else if (Object.keys(MONITOR).length) {{
    bar.style.display = 'block';
    bar.style.background = '#0d1117';
    bar.style.color = '#d29922';
    bar.innerHTML = '\u25cb ' + t('monitoring_inactive');
  }} else {{
    bar.style.display = 'none';
  }}
}}

// ── Language toggle ──
function updateLangBtn() {{
  var btn = document.getElementById('lang-btn');
  if (btn) btn.textContent = LANG === 'en' ? 'PL' : 'EN';
  var em = document.getElementById('empty-msg');
  if (em && em.parentElement.querySelector('.card') === null) em.textContent = t('select_session');
}}

function toggleLang() {{
  LANG = LANG === 'en' ? 'pl' : 'en';
  localStorage.setItem('nm_lang', LANG);
  updateLangBtn();
  renderSidebar();
  if (activeIdx >= 0 && activeIdx < DATA.length) selectSession(activeIdx);
  renderStatusBar();
}}

// ── Init ──
var savedLang = localStorage.getItem('nm_lang');
if (savedLang) LANG = savedLang;
updateLangBtn();
document.getElementById('empty-msg').textContent = t('select_session');
renderSidebar();
if (DATA.length) selectSession(DATA.length - 1);
renderStatusBar();
{live_js}
</script>
</body>
</html>'''


# ── Main Monitor Loop ─────────────────────────────────────────────────────

def monitor():
    ensure_dirs()

    if not acquire_lock():
        sys.exit(1)

    session_dir = setup_session_dir()
    init_csv()

    # Gather network environment
    net_env = gather_network_env()
    isp_args = get_isp_counterarguments(net_env)

    # Write connection info file + log session start
    write_connection_info(net_env, isp_args)
    log_event("session_start", {
        "session_dir": str(session_dir),
        "platform": sys.platform,
        "platform_name": PLATFORM_NAME,
        "network_env": net_env,
        "isp_counterarguments": isp_args,
        "config": {
            "runs_per_target": RUNS_PER_TARGET,
            "max_hops": MAX_HOPS,
            "loss_threshold": LOSS_THRESHOLD,
            "trace_targets": TRACE_TARGETS,
            "ping_targets": PING_TARGETS,
        },
    })

    print(f"\n{BOLD}Net Monitor -- ISP Complaint Evidence Builder{RESET}")
    print(f"{DIM}  Sesja:   {session_dir}")
    print(f"  Platforma: {PLATFORM_NAME} ({sys.platform})")
    print(f"  Runs/target: {RUNS_PER_TARGET} | Max hops: {MAX_HOPS}")
    print(f"  Targets: {', '.join(list(TRACE_TARGETS.keys()) + list(PING_TARGETS.keys()))}")
    print_network_env_short(net_env)
    print(f"  Ctrl+C aby zatrzymac{RESET}\n")

    cycle = 0
    last_speed_test = 0
    session_start = time.time()

    previous_routes = {}  # target -> list of hop IPs (for route stability)
    route_changes = 0

    drop_state = {
        "in_drop": False,
        "start_time": None,
        "start_ts": None,
        "fault_zone": "UNKNOWN",
        "detail": "",
    }

    stats = {
        "total_runs": 0,
        "ok_runs": 0,
        "fail_runs": 0,
        "total_incidents": 0,
        "total_drops": 0,
        "total_drop_seconds": 0.0,
        "zone_incidents": defaultdict(int),
        "zone_faults": defaultdict(int),
        "hop_reached": defaultdict(int),
        "hop_failed": defaultdict(int),
        "hop_tested": defaultdict(int),
        "hop_zones": {},
    }

    shutdown_requested = False

    def handle_signal(sig, frame):
        nonlocal shutdown_requested
        shutdown_requested = True

    def is_shutdown():
        return shutdown_requested

    signal.signal(signal.SIGINT, handle_signal)
    if not IS_WINDOWS:
        signal.signal(signal.SIGTERM, handle_signal)

    try:
        while not shutdown_requested:
            cycle += 1
            ts = ts_now()
            ts_s = ts_short()

            # Re-gather network env every cycle (log only, show only on change)
            cur_env = gather_network_env()
            env_changed = (cur_env.get("interface") != net_env.get("interface") or
                           cur_env.get("interface_type") != net_env.get("interface_type") or
                           cur_env.get("wifi_ssid") != net_env.get("wifi_ssid") or
                           cur_env.get("ip") != net_env.get("ip") or
                           cur_env.get("gateway") != net_env.get("gateway"))

            print(f"\n{DIM}{'─'*60}")
            print(f"Cykl #{cycle}  {ts}{RESET}")

            if env_changed:
                net_env = cur_env
                print(f"  {YELLOW}Zmiana sieci:{RESET}")
                print_network_env_short(net_env)
            else:
                # Always show WiFi signal for variability tracking
                net_env = cur_env
                print_network_env_short(net_env)

            log_event("cycle_start", {
                "cycle": cycle,
                "platform": PLATFORM_NAME,
                "network_env": cur_env,
            })

            # --- Trace targets ---
            cycle_ok = 0
            cycle_fail = 0
            cycle_faults = []
            any_target_reachable = False

            for name, target in TRACE_TARGETS.items():
                if shutdown_requested:
                    break
                result = run_trace_cycle(name, target, cycle, stats, is_shutdown)

                # Route stability check
                new_route = result.get("route", [])
                if new_route and name in previous_routes:
                    old_route = previous_routes[name]
                    if new_route != old_route:
                        route_changes += 1
                        log_event("route_change", {
                            "target_name": name, "target": target,
                            "cycle": cycle,
                            "old_route": old_route, "new_route": new_route,
                        })
                        print(f"  {YELLOW}Route change to {name}!{RESET}")
                if new_route:
                    previous_routes[name] = new_route
                cycle_ok += result["ok_runs"]
                cycle_fail += result["fail_runs"]
                cycle_faults.extend(result["faults"])
                if result["ok_runs"] > 0:
                    any_target_reachable = True

            if shutdown_requested:
                break

            # --- DNS resolution test ---
            dns_results = test_dns_resolution()
            if dns_results:
                avg_dns = sum(r["time_ms"] for r in dns_results if r["ok"]) / max(1, sum(1 for r in dns_results if r["ok"]))
                log_event("dns_test", {"cycle": cycle, "results": dns_results, "avg_ms": round(avg_dns, 1)})
                dns_ok = [r for r in dns_results if r["ok"]]
                if dns_ok:
                    dns_max = max(r["time_ms"] for r in dns_ok)
                    color = RED if dns_max > 100 else (YELLOW if dns_max > 50 else GREEN)
                    print(f"  {DIM}DNS: avg {avg_dns:.0f}ms, max {dns_max:.0f}ms{RESET}", end="")
                    if dns_max > 100:
                        print(f"  {RED}(slow!){RESET}", end="")
                    print()

            # --- Quick ping targets (batch) ---
            ping_ok = 0
            ping_total = len(PING_TARGETS)
            for name, target in PING_TARGETS.items():
                if shutdown_requested:
                    break
                try:
                    if IS_WINDOWS:
                        cmd = ["ping", "-n", "1", "-w", "2000", target]
                    else:
                        cmd = ["ping", "-c", "1", "-W", "2", target]
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    if r.returncode == 0:
                        ping_ok += 1
                        any_target_reachable = True
                except Exception:
                    pass

            if shutdown_requested:
                break

            # --- Drop detection ---
            all_unreachable = not any_target_reachable
            total_targets = len(TRACE_TARGETS) + len(PING_TARGETS)

            if all_unreachable:
                if not drop_state["in_drop"]:
                    drop_state["in_drop"] = True
                    drop_state["start_time"] = time.time()
                    drop_state["start_ts"] = ts
                    # Determine fault zone from faults
                    if cycle_faults:
                        zone_cnt = defaultdict(int)
                        for f in cycle_faults:
                            zone_cnt[f["zone"]] += 1
                        drop_state["fault_zone"] = max(zone_cnt, key=zone_cnt.get)
                        worst = [f for f in cycle_faults
                                 if f["zone"] == drop_state["fault_zone"]][0]
                        drop_state["detail"] = (f"hop {worst['hop_num']} "
                                                f"[{worst['zone']}] {worst['host']}")
                    else:
                        drop_state["fault_zone"] = "UNKNOWN"
                        drop_state["detail"] = ""

                    print_drop_start(ts_s, drop_state["fault_zone"],
                                     drop_state["detail"], total_targets)
                    log_event("drop_start", {
                        "cycle": cycle, "fault_zone": drop_state["fault_zone"],
                        "detail": drop_state["detail"],
                    })
                else:
                    elapsed = time.time() - drop_state["start_time"]
                    print_drop_continues(ts_s, elapsed, drop_state["fault_zone"])
            else:
                if drop_state["in_drop"]:
                    duration = time.time() - drop_state["start_time"]
                    csv_append(DROPS_LOG, [
                        drop_state["start_ts"], ts, round(duration, 1),
                        drop_state["fault_zone"], drop_state["detail"],
                    ])
                    stats["total_drops"] += 1
                    stats["total_drop_seconds"] += duration
                    drop_state["in_drop"] = False

                    print_drop_ended(ts_s, duration, drop_state["fault_zone"])
                    log_event("drop_end", {
                        "cycle": cycle, "duration_seconds": round(duration, 1),
                        "fault_zone": drop_state["fault_zone"],
                    })

            # --- Cycle summary line ---
            total = cycle_ok + cycle_fail
            if total > 0:
                elapsed_session = time.time() - session_start
                drop_t = stats["total_drop_seconds"]
                if drop_state["in_drop"]:
                    drop_t += time.time() - drop_state["start_time"]
                uptime = max(0, 100 * (1 - drop_t / elapsed_session)) if elapsed_session > 0 else 100

                if cycle_fail == 0:
                    print(f"{GREEN}[{ts_s}] Cykl #{cycle}: {cycle_ok}/{total} OK "
                          f"| pings: {ping_ok}/{ping_total} "
                          f"| uptime {uptime:.1f}%{RESET}")
                else:
                    print(f"{YELLOW}[{ts_s}] Cykl #{cycle}: {cycle_ok}/{total} OK, "
                          f"{cycle_fail} fail "
                          f"| pings: {ping_ok}/{ping_total} "
                          f"| uptime {uptime:.1f}%{RESET}")

            log_event("cycle_end", {
                "cycle": cycle, "ok": cycle_ok, "fail": cycle_fail,
                "pings_ok": ping_ok, "pings_total": ping_total,
            })

            # --- Speed test ---
            now_t = time.time()
            if now_t - last_speed_test > SPEED_TEST_INTERVAL:
                speed = estimate_speed()
                if speed:
                    csv_append(SPEED_LOG, [
                        ts, speed["test_name"], speed["speed_mbps"],
                        speed["time_seconds"], speed["http_code"],
                        speed.get("dns_ms", ""), speed.get("connect_ms", ""),
                        speed.get("tls_ms", ""), speed.get("ttfb_ms", ""),
                    ])
                    log_event("speed_test", speed)
                    print(f"  {DIM}Download: {speed['speed_mbps']} Mbps{RESET}", end="")
                    if speed.get("dns_ms"):
                        print(f"  {DIM}| DNS {speed['dns_ms']:.0f}ms "
                              f"| TCP {speed['connect_ms']:.0f}ms "
                              f"| TLS {speed['tls_ms']:.0f}ms "
                              f"| TTFB {speed['ttfb_ms']:.0f}ms{RESET}", end="")
                    print()

                upload = estimate_upload_speed()
                if upload:
                    csv_append(SPEED_LOG, [
                        ts, upload["test_name"], upload["speed_mbps"],
                        upload["time_seconds"], upload["http_code"],
                        "", "", "", "",
                    ])
                    log_event("speed_test", upload)
                    print(f"  {DIM}Upload: {upload['speed_mbps']} Mbps{RESET}")

                last_speed_test = now_t

            # --- Periodic stats ---
            if cycle % STATS_EVERY_N_CYCLES == 0:
                elapsed_session = time.time() - session_start
                drop_t = stats["total_drop_seconds"]
                if drop_state["in_drop"]:
                    drop_t += time.time() - drop_state["start_time"]
                uptime = max(0, 100 * (1 - drop_t / elapsed_session)) if elapsed_session > 0 else 100
                total_r = stats["total_runs"]
                ok_r = stats["ok_runs"]
                print(f"\n{DIM}-- Po {cycle} cyklach: {ok_r}/{total_r} runs OK "
                      f"| {stats['total_incidents']} incydentow "
                      f"| {stats['total_drops']} dropow "
                      f"| uptime {uptime:.1f}% --{RESET}\n")

            # No sleep between cycles — continuous data collection

    except Exception as e:
        print(f"\n{RED}Error: {e}{RESET}")
        import traceback
        traceback.print_exc()
        release_lock()

    # --- Graceful shutdown ---
    elapsed = time.time() - session_start
    drop_time = stats["total_drop_seconds"]
    if drop_state["in_drop"]:
        duration = time.time() - drop_state["start_time"]
        csv_append(DROPS_LOG, [
            drop_state["start_ts"], ts_now(), round(duration, 1),
            drop_state["fault_zone"], drop_state["detail"],
        ])
        stats["total_drops"] += 1
        drop_time += duration

    uptime = max(0, 100 * (1 - drop_time / elapsed)) if elapsed > 0 else 100

    log_event("session_end", {
        "platform": PLATFORM_NAME,
        "cycles": cycle, "elapsed_seconds": round(elapsed, 1),
        "total_runs": stats["total_runs"],
        "ok_runs": stats["ok_runs"],
        "fail_runs": stats["fail_runs"],
        "incidents": stats["total_incidents"],
        "drops": stats["total_drops"],
        "downtime_seconds": round(drop_time, 1),
        "uptime_pct": round(uptime, 1),
        "route_changes": route_changes,
    })

    print_session_summary(cycle, elapsed, stats, drop_time, uptime)
    release_lock()


# ── Clean / Purge ────────────────────────────────────────────────────────

def clean_logs(mode="all", keep_days=None):
    """Remove collected data so old sessions don't interfere with new analysis.

    Modes:
      all        — delete everything (output/ + reports/)
      sessions   — delete only session output dirs (keep reports)
      reports    — delete only generated reports
      older N    — delete sessions older than N days (keep_days param)
    """
    ensure_dirs()

    removed_sessions = 0
    removed_reports = 0

    if mode in ("all", "sessions", "older"):
        if OUTPUT_DIR.exists():
            cutoff_name = None
            if mode == "older" and keep_days is not None:
                cutoff = datetime.now() - timedelta(days=keep_days)
                cutoff_name = cutoff.strftime("%Y%m%d_%H%M%S")

            for session_dir in sorted(OUTPUT_DIR.iterdir()):
                if not session_dir.is_dir():
                    continue
                if cutoff_name and session_dir.name >= cutoff_name:
                    continue  # keep — newer than cutoff
                # Remove session dir and all its contents
                try:
                    import shutil
                    shutil.rmtree(session_dir)
                    removed_sessions += 1
                except OSError as e:
                    print(f"{RED}Nie mozna usunac {session_dir}: {e}{RESET}")

    if mode in ("all", "reports"):
        if REPORT_DIR.exists():
            for f in REPORT_DIR.iterdir():
                if f.is_file():
                    try:
                        f.unlink()
                        removed_reports += 1
                    except OSError as e:
                        print(f"{RED}Nie mozna usunac {f}: {e}{RESET}")

    # Summary
    print(f"\n{'='*50}")
    print(f"  {BOLD}Czyszczenie zakonczono{RESET}")
    print(f"{'='*50}")
    if removed_sessions:
        print(f"  Usuniete sesje:   {GREEN}{removed_sessions}{RESET}")
    if removed_reports:
        print(f"  Usuniete raporty: {GREEN}{removed_reports}{RESET}")
    if removed_sessions == 0 and removed_reports == 0:
        print(f"  {DIM}Nic do usuniecia.{RESET}")

    # Show what remains
    remaining = 0
    if OUTPUT_DIR.exists():
        remaining = sum(1 for d in OUTPUT_DIR.iterdir() if d.is_dir())
    if remaining:
        print(f"  Pozostalo sesji:  {remaining}")
    print(f"{'='*50}")


def list_sessions():
    """List all session directories with basic stats."""
    ensure_dirs()
    if not OUTPUT_DIR.exists():
        print(f"{DIM}Brak sesji.{RESET}")
        return

    sessions = sorted(d for d in OUTPUT_DIR.iterdir() if d.is_dir())
    if not sessions:
        print(f"{DIM}Brak sesji.{RESET}")
        return

    print(f"\n{BOLD}Sesje ({len(sessions)}):{RESET}")
    print(f"  {'Nazwa':<20} {'Pliki':>6} {'Rozmiar':>10}")
    print(f"  {'-'*40}")

    total_size = 0
    for sd in sessions:
        files = list(sd.iterdir())
        size = sum(f.stat().st_size for f in files if f.is_file())
        total_size += size
        size_str = _fmt_size(size)
        print(f"  {sd.name:<20} {len(files):>6} {size_str:>10}")

    print(f"  {'-'*40}")
    print(f"  {'Lacznie':<20} {'':>6} {_fmt_size(total_size):>10}")
    print()


def _fmt_size(n):
    if n < 1024:
        return f"{n} B"
    elif n < 1024 * 1024:
        return f"{n/1024:.1f} KB"
    else:
        return f"{n/1024/1024:.1f} MB"


# ── CLI ───────────────────────────────────────────────────────────────────

def print_help():
    """Print a friendly, colorful help screen."""
    print(f"""
{BOLD}Net Monitor — ISP Complaint Evidence Builder{RESET}
{DIM}Zbiera twarde dowody na problemy z dostawca internetu{RESET}

{BOLD}Uzycie:{RESET}
  python3 net_monitor.py {DIM}[opcja]{RESET}

{BOLD}Tryby pracy:{RESET}
  {GREEN}(brak opcji){RESET}            Uruchom monitoring (ciagly, Ctrl+C aby zatrzymac)
  {GREEN}--report{RESET}                Generuj raport Markdown + JSON z zebranych danych
  {GREEN}--dashboard{RESET}             Generuj interaktywny HTML dashboard i otworz w przegladarce
  {GREEN}--live{RESET}                  Dashboard na zywo — auto-refresh co 5s (serwer HTTP)

{BOLD}Zarzadzanie danymi:{RESET}
  {GREEN}--list{RESET}                  Wyswietl liste sesji z rozmiarem
  {GREEN}--clean{RESET}                 Usun WSZYSTKIE dane (sesje + raporty)
  {GREEN}--clean sessions{RESET}        Usun tylko sesje (zachowaj raporty)
  {GREEN}--clean reports{RESET}         Usun tylko raporty (zachowaj sesje)
  {GREEN}--clean older{RESET}           Usun sesje starsze niz --days dni

{BOLD}Opcje:{RESET}
  {GREEN}--days N{RESET}                Okres w dniach — dla raportu/dashboardu/clean older
                          {DIM}(domyslnie: 30){RESET}
  {GREEN}--port N{RESET}                Port serwera HTTP dla --live {DIM}(domyslnie: 8077){RESET}

{BOLD}Przyklady:{RESET}
  {DIM}# Nowy pomiar od zera:{RESET}
  python3 net_monitor.py --clean
  python3 net_monitor.py

  {DIM}# Raport z ostatnich 7 dni:{RESET}
  python3 net_monitor.py --report --days 7

  {DIM}# Dashboard ze wszystkich sesji:{RESET}
  python3 net_monitor.py --dashboard

  {DIM}# Live dashboard (odswiezany co 5s):{RESET}
  python3 net_monitor.py --live

  {DIM}# Porzadki — usun stare, zostaw ostatni tydzien:{RESET}
  python3 net_monitor.py --clean older --days 7

{BOLD}Jak to dziala:{RESET}
  1. {GREEN}traceroute{RESET}    Odkrywa trase do celu (hop po hopie)
  2. {GREEN}TTL ping{RESET}      {RUNS_PER_TARGET} prob per cel — pakiet z rosnacym TTL (1,2,3...)
                   pokazuje dokladnie ktory hop przechodzi a ktory gubi pakiety
  3. {GREEN}ping{RESET}          Szybkie sprawdzenie dodatkowych celow
  4. {GREEN}curl{RESET}          Periodyczny test predkosci

{BOLD}Strefy usterek:{RESET}
  {GREEN}LOCAL{RESET}      hop 1     Router / WiFi klienta
  {RED}ISP_EDGE{RESET}   hop 2     Pierwsze urzadzenie dostawcy
  {RED}ISP_CORE{RESET}   hop 3-4   Szkielet sieci dostawcy
  {DIM}TRANSIT{RESET}    hop 5+    Siec tranzytowa (poza ISP)

{BOLD}Cele testowe:{RESET}
  Trace:  {', '.join(f'{n} ({ip})' for n, ip in TRACE_TARGETS.items())}
  Ping:   {', '.join(f'{n} ({ip})' for n, ip in PING_TARGETS.items())}

{BOLD}Dane:{RESET}  {DIM}{DATA_DIR}{RESET}
""")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Net Monitor -- ISP Complaint Evidence Builder",
        add_help=False,
    )
    parser.add_argument("-h", "--help", action="store_true",
                        help="Pokaz pomoc")
    parser.add_argument("--report", action="store_true",
                        help="Generuj raport MD+JSON z zebranych danych")
    parser.add_argument("--dashboard", action="store_true",
                        help="Generuj HTML dashboard i otworz w przegladarce")
    parser.add_argument("--live", action="store_true",
                        help="Live dashboard z auto-refresh (serwer HTTP)")
    parser.add_argument("--port", type=int, default=8077,
                        help="Port serwera HTTP dla --live (domyslnie: 8077)")
    parser.add_argument("--list", action="store_true",
                        help="Wylistuj wszystkie sesje")
    parser.add_argument("--clean", nargs="?", const="all",
                        metavar="MODE",
                        help="Usun dane: all (domyslnie), sessions, reports, older")
    parser.add_argument("--days", type=int, default=30,
                        help="Okres raportu / progu czyszczenia w dniach (domyslnie: 30)")
    args = parser.parse_args()

    if args.help:
        print_help()
    elif args.list:
        list_sessions()
    elif args.clean:
        mode = args.clean
        if mode not in ("all", "sessions", "reports", "older"):
            print(f"{RED}Nieznany tryb: {mode}. Uzyj: all, sessions, reports, older{RESET}")
            sys.exit(1)
        if mode == "all":
            print(f"{YELLOW}Usuwanie WSZYSTKICH danych z {DATA_DIR}...{RESET}")
        elif mode == "older":
            print(f"{YELLOW}Usuwanie sesji starszych niz {args.days} dni...{RESET}")
        else:
            print(f"{YELLOW}Usuwanie: {mode}...{RESET}")
        clean_logs(mode=mode, keep_days=args.days)
    elif args.live:
        live_dashboard(args.days, args.port)
    elif args.dashboard:
        generate_dashboard(args.days)
    elif args.report:
        generate_report(args.days)
    else:
        monitor()
