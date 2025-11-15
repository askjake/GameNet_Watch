# netwatch_gaming/app.py
import os
import re
import sys
import time
import math
import csv
import json
import queue
import threading
import platform
import subprocess
from collections import deque, defaultdict
from datetime import datetime, timedelta
import socket
import ipaddress
from pathlib import Path

import numpy as np
import pandas as pd
import streamlit as st

# Optional deps guarded to keep the app resilient
try:
    import dns.resolver  # dnspython
except Exception:
    dns = None

try:
    import speedtest  # speedtest-cli
except Exception:
    speedtest = None

try:
    import netifaces  # default gateway detection
except Exception:
    netifaces = None

try:
    import psutil  # for system stats, conn table and io counters
except Exception:
    psutil = None

APP_TITLE = "GameNet Watch — Real-time Network Monitor"
APP_VER = "1.4.0"

# ------------------ Utilities ------------------
def now_ts():
    return time.time()

def human_ts(ts=None):
    return datetime.fromtimestamp(ts or time.time()).strftime("%Y-%m-%d %H:%M:%S")

def default_gateway_v4():
    try:
        if netifaces:
            gws = netifaces.gateways()
            if 'default' in gws and netifaces.AF_INET in gws['default']:
                return gws['default'][netifaces.AF_INET][0]
    except Exception:
        pass
    try:
        if platform.system() == "Windows":
            out = subprocess.run(["route", "print", "-4"], capture_output=True, text=True, timeout=3)
            m = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", out.stdout)
            if m:
                return m.group(1)
        else:
            out = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=3)
            m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out.stdout)
            if m:
                return m.group(1)
    except Exception:
        pass
    return "192.168.1.1"

def parse_ping_ms(stdout_text):
    s = stdout_text.lower()
    m = re.search(r"time[=<]?\s*([\d\.]+)\s*ms", s)
    if m:
        return float(m.group(1))
    m = re.search(r"average\s*=\s*([\d\.]+)\s*ms", s)   # Windows 'Average = Xms'
    if m:
        return float(m.group(1))
    m = re.search(r"round-trip.*=\s*[\d\.]+/([\d\.]+)/", s)  # macOS avg
    if m:
        try:
            return float(m.group(1))
        except:
            return None
    return None

def ping_once(host: str, timeout_ms: int = 1000):
    if platform.system() == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
    else:
        cmd = ["ping", "-c", "1", host]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=max(1.0, timeout_ms/1000.0 + 0.5))
        if proc.returncode == 0:
            return parse_ping_ms(proc.stdout)
        else:
            ms = parse_ping_ms(proc.stdout)
            return ms
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None

def calc_jitter_mean_abs_diffs(values):
    vals = [v for v in values if v is not None]
    if len(vals) < 2:
        return 0.0
    diffs = [abs(vals[i] - vals[i-1]) for i in range(1, len(vals))]
    return float(sum(diffs) / len(diffs))

# ------------------ Throughput Hints ------------------
def bytes_per_sec_to_human(bps):
    if bps is None:
        return "N/A"
    units = ["B/s","KB/s","MB/s","GB/s"]
    i=0
    while bps>=1024 and i < len(units)-1:
        bps/=1024.0; i+=1
    return f"{bps:.1f} {units[i]}"

def iface_rates_psutil(prev, cur, dt):
    rates = {}
    for nic, stats in cur.items():
        if nic in prev:
            d_rx = max(0, cur[nic].bytes_recv - prev[nic].bytes_recv)
            d_tx = max(0, cur[nic].bytes_sent - prev[nic].bytes_sent)
            rates[nic] = {"rx_Bps": d_rx/dt, "tx_Bps": d_tx/dt}
    return rates

def linux_socket_hints():
    """Parse 'ss -tin state established' for cwnd and rtt hints."""
    try:
        out = subprocess.run(["ss","-tin","state","established"], capture_output=True, text=True, timeout=2)
        cwnds=[]; rtts=[]
        for line in out.stdout.splitlines():
            m_rtt = re.search(r"rtt[: ]([\d\.]+)/", line)
            m_cwnd = re.search(r"cwnd[: ](\d+)", line)
            if m_rtt:
                try: rtts.append(float(m_rtt.group(1)))
                except: pass
            if m_cwnd:
                try: cwnds.append(int(m_cwnd.group(1)))
                except: pass
        hints = {}
        if rtts: hints["rtt_ms_med"] = float(np.median(rtts))
        if cwnds: hints["cwnd_pkts_med"] = float(np.median(cwnds))
        if rtts and cwnds:
            mss = 1460.0
            bdp_bytes = hints["cwnd_pkts_med"] * mss
            hints["bdp_bytes"] = bdp_bytes
            hints["rough_tp_Mbps"] = (bdp_bytes*8.0) / (hints["rtt_ms_med"]/1000.0) / 1e6
        return hints
    except Exception:
        return {}

def macos_top_talkers():
    """Try 'nettop' one-shot; fallback empty."""
    try:
        out = subprocess.run(["nettop","-P","-L","1","-x","-J","bytes_in,bytes_out"], capture_output=True, text=True, timeout=3)
        # Summarize total observed in/out over this 1s window
        bytes_in = 0; bytes_out = 0
        for line in out.stdout.splitlines():
            # Lines might contain "bytes_in:12345 bytes_out:6789"
            mi = re.search(r"bytes_in:(\d+)", line)
            mo = re.search(r"bytes_out:(\d+)", line)
            if mi: bytes_in += int(mi.group(1))
            if mo: bytes_out += int(mo.group(1))
        if bytes_in or bytes_out:
            return {"observed_rx_Bps": float(bytes_in), "observed_tx_Bps": float(bytes_out)}
    except Exception:
        pass
    return {}

def windows_net_bytes():
    """Try 'netstat -e' snapshot to supplement psutil."""
    try:
        out = subprocess.run(["netstat","-e"], capture_output=True, text=True, timeout=2)
        # 'Bytes' line contains Received and Sent totals
        m = re.search(r"^\s*Bytes\s+(\d+)\s+(\d+)", out.stdout, re.M)
        if m:
            rx = int(m.group(1)); tx = int(m.group(2))
            return {"totals_rx": rx, "totals_tx": tx}
    except Exception:
        pass
    return {}

def throughput_hints_tick(state):
    """Compute per-interface throughput via psutil deltas; plus OS-specific extras."""
    if not psutil:
        return {"error":"psutil not installed"}
    t0 = now_ts()
    cur0 = psutil.net_io_counters(pernic=True)
    time.sleep(0.5)  # short sampling window
    cur1 = psutil.net_io_counters(pernic=True)
    t1 = now_ts()
    rates = iface_rates_psutil(cur0, cur1, max(0.1, t1-t0))
    hints = {"iface_rates": rates}
    sysname = platform.system()
    if sysname == "Linux":
        hints["socket"] = linux_socket_hints()
    elif sysname == "Darwin":
        hints["top_talkers"] = macos_top_talkers()
    elif sysname == "Windows":
        hints["net_bytes"] = windows_net_bytes()
    return hints

# ------------------ Connection sampler ------------------
class ConnSampler:
    def __init__(self, interval_sec=2.0, window=30, min_seen=3):
        self.interval_sec = interval_sec
        self.window = window
        self.min_seen = min_seen
        self.snapshots = deque(maxlen=window)
        self._thread = None
        self._stop = threading.Event()

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="ConnSampler", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _run(self):
        while not self._stop.is_set():
            self._take_snapshot()
            time.sleep(self.interval_sec)

    def _take_snapshot(self):
        snap = defaultdict(lambda: {"count": 0, "ports": set(), "pids": set()})
        ts = now_ts()
        if not psutil:
            self.snapshots.append({"ts": ts, "data": {}})
            return
        try:
            conns = psutil.net_connections(kind='inet')
        except Exception:
            self.snapshots.append({"ts": ts, "data": {}})
            return

        for c in conns:
            if not c.raddr:
                continue
            rip = c.raddr.ip if hasattr(c.raddr, "ip") else c.raddr[0]
            rport = c.raddr.port if hasattr(c.raddr, "port") else (c.raddr[1] if len(c.raddr) > 1 else None)
            if c.type not in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                continue
            if c.type == socket.SOCK_STREAM and c.status not in ("ESTABLISHED", "CLOSE_WAIT", "SYN_SENT"):
                continue
            entry = snap[rip]
            entry["count"] += 1
            if rport:
                entry["ports"].add(int(rport))
            if c.pid:
                entry["pids"].add(int(c.pid))

        self.snapshots.append({"ts": ts, "data": snap})

    def rank_endpoints(self, port_filter=None, include_private=True):
        agg = {}
        now = now_ts()
        for snap in self.snapshots:
            data = snap["data"]
            for ip, d in data.items():
                try:
                    if (not include_private) and ipaddress.ip_address(ip).is_private:
                        continue
                except Exception:
                    pass
                if port_filter:
                    if not any(port_filter(p) for p in d["ports"]) and d["ports"]:
                        continue
                a = agg.setdefault(ip, {"seen":0,"score":0.0,"ports":set(),"pids":set(),"cur_conns":0,"last_seen_ts":0.0})
                a["seen"] += 1
                a["score"] += d["count"] + 0.5
                a["ports"].update(d["ports"])
                a["pids"].update(d["pids"])
                a["cur_conns"] = d["count"]
                a["last_seen_ts"] = snap["ts"]
        ranked = []
        for ip, a in agg.items():
            if a["seen"] < self.min_seen:
                continue
            ranked.append({
                "ip": ip,
                "score": a["score"],
                "seen": a["seen"],
                "cur_conns": a["cur_conns"],
                "ports": sorted(list(a["ports"])),
                "pids": sorted(list(a["pids"])),
                "last_seen_ts": a["last_seen_ts"],
                "age_sec": now - a["last_seen_ts"],
            })
        ranked.sort(key=lambda x: (-x["score"], x["age_sec"]))
        return ranked

# ------------------ Reverse DNS / proc name caches ------------------
@st.cache_data(show_spinner=False, ttl=300)
def rdns_lookup(ip: str):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

@st.cache_data(show_spinner=False, ttl=120)
def pid_names(pids):
    names = []
    if not psutil:
        return names
    for pid in pids:
        try:
            p = psutil.Process(pid)
            names.append(p.name())
        except Exception:
            continue
    out = []
    for n in names:
        if n not in out:
            out.append(n)
    return out[:5]

# ------------------ Port filter ------------------
def make_port_filter(spec: str):
    ranges = []
    for tok in re.split(r"[,\s]+", spec.strip()):
        if not tok:
            continue
        if "-" in tok:
            a,b = tok.split("-",1)
            try:
                a=int(a); b=int(b)
                if 0<=a<=65535 and 0<=b<=65535 and a<=b:
                    ranges.append((a,b))
            except:
                continue
        else:
            try:
                p=int(tok)
                if 0<=p<=65535:
                    ranges.append((p,p))
            except:
                continue
    if not ranges:
        return None
    def _f(p):
        for a,b in ranges:
            if a<=p<=b: return True
        return False
    return _f

# ------------------ Ping monitor ------------------
class PingMonitor:
    def __init__(self, host: str, interval_ms: int = 1000, window: int = 120):
        self.host = host
        self.interval_ms = interval_ms
        self.window = window
        self.samples = deque(maxlen=window)
        self.timestamps = deque(maxlen=window)
        self.total_sent = 0
        self.total_lost = 0
        self._thread = None
        self._stop_evt = threading.Event()

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_evt.clear()
        self._thread = threading.Thread(target=self._run, name=f"PingMon-{self.host}", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_evt.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _run(self):
        while not self._stop_evt.is_set():
            self.total_sent += 1
            ms = ping_once(self.host, timeout_ms=min(2000, self.interval_ms))
            if ms is None:
                self.total_lost += 1
            self.samples.append(ms)
            self.timestamps.append(now_ts())
            time.sleep(max(0.05, self.interval_ms/1000.0))

    def metrics(self):
        vals = [v for v in self.samples if v is not None]
        avg = float(np.mean(vals)) if vals else None
        p95 = float(np.percentile(vals, 95)) if len(vals) >= 2 else (vals[0] if len(vals)==1 else None)
        worst = float(np.max(vals)) if vals else None
        jitter = calc_jitter_mean_abs_diffs(self.samples)
        loss_recent = 100.0 * (self.samples.count(None) / len(self.samples)) if len(self.samples) else 0.0
        loss_total = 100.0 * (self.total_lost / self.total_sent) if self.total_sent else 0.0
        return {
            "avg_ms": avg,
            "p95_ms": p95,
            "worst_ms": worst,
            "jitter_ms": jitter,
            "loss_recent_pct": loss_recent,
            "loss_total_pct": loss_total,
            "n": len(self.samples),
        }

# ------------------ Streamlit state ------------------
def init_state():
    if "monitors" not in st.session_state:
        st.session_state.monitors = {}
    if "running" not in st.session_state:
        st.session_state.running = False
    if "refresh_ms" not in st.session_state:
        st.session_state.refresh_ms = 1000
    if "sampler" not in st.session_state:
        st.session_state.sampler = ConnSampler(interval_sec=2.0, window=24, min_seen=3)
        st.session_state.sampler.start()
    if "auto_targets" not in st.session_state:
        st.session_state.auto_targets = []
    if "sticky" not in st.session_state:
        st.session_state.sticky = {}  # ip -> expiry_ts
    if "ops" not in st.session_state:
        st.session_state.ops = {
            "dns": {"start": False, "result": None, "args": None},
            "speed": {"start": False, "result": None},
            "trace": {"start": False, "result": None, "args": None},
        }
    if "logging" not in st.session_state:
        st.session_state.logging = {"enabled": False, "dir": str(Path.cwd() / "logs"), "metrics_file": None, "discover_file": None}
    return st.session_state

# ------------------ CSV logging ------------------
def ensure_log_files(state):
    logdir = Path(state.logging["dir"])
    logdir.mkdir(parents=True, exist_ok=True)
    if not state.logging["metrics_file"]:
        fn = logdir / f"metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(fn, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["ts_iso","target","avg_ms","jitter_ms","p95_ms","worst_ms","loss_recent_pct","loss_total_pct","n"])
        state.logging["metrics_file"] = str(fn)
    if not state.logging["discover_file"]:
        fn = logdir / f"discover_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(fn, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["ts_iso","ip","host","ports","score","seen","cur_conns","age_sec"])
        state.logging["discover_file"] = str(fn)

def log_metrics_row(state, target, m):
    try:
        if not (state.logging["enabled"] and state.logging["metrics_file"]):
            return
        with open(state.logging["metrics_file"], "a", newline="") as f:
            w = csv.writer(f)
            w.writerow([datetime.now().isoformat(timespec="seconds"), target, m["avg_ms"], m["jitter_ms"], m["p95_ms"], m["worst_ms"], m["loss_recent_pct"], m["loss_total_pct"], m["n"]])
    except Exception:
        pass

def log_discover_rows(state, ranked):
    try:
        if not (state.logging["enabled"] and state.logging["discover_file"]):
            return
        with open(state.logging["discover_file"], "a", newline="") as f:
            w = csv.writer(f)
            for r in ranked:
                w.writerow([datetime.now().isoformat(timespec="seconds"), r["ip"], rdns_lookup(r["ip"]), ";".join(map(str,r["ports"])), r["score"], r["seen"], r["cur_conns"], int(r["age_sec"])])
    except Exception:
        pass

# ------------------ UI ------------------
st.set_page_config(page_title=APP_TITLE, layout="wide")
st.title(APP_TITLE)
st.caption(f"v{APP_VER} — Gaming metrics + Auto-Discover + Throughput Hints + Sticky Targets + CSV logs")
state = init_state()

with st.sidebar:
    st.header("Targets & Settings")
    gw = default_gateway_v4()
    default_targets = [gw, "1.1.1.1", "8.8.8.8", "www.google.com"]
    targets_text = st.text_area("Manual ping targets (one per line)", value="\n".join(default_targets), height=120)
    interval_ms = st.slider("Ping interval (ms)", min_value=200, max_value=2000, value=1000, step=100)
    window = st.slider("Sliding window (samples)", min_value=30, max_value=600, value=180, step=30)
    refresh_ms = st.slider("UI refresh (ms)", min_value=500, max_value=5000, value=1000, step=500)
    state.refresh_ms = refresh_ms

    st.divider()
    st.subheader("Auto-Discover")
    enable_auto = st.checkbox("Enable auto-discovery", value=True)
    top_n = st.number_input("Monitor top N endpoints", min_value=1, max_value=10, value=3, step=1)
    stickiness_min = st.slider("Stickiness (minutes)", min_value=1, max_value=60, value=10, step=1, help="Auto-selected endpoints stay monitored at least this long.")
    stickiness_secs = stickiness_min * 60
    min_snap = st.slider("Minimum snapshots seen", min_value=1, max_value=10, value=3, step=1)
    port_spec = st.text_input("Optional port filter", value="3074, 27015-27050, 3478-3480")
    include_private = st.checkbox("Include LAN/private IPs", value=True)
    replace_manual = st.checkbox("Replace manual targets (instead of augmenting)", value=False)

    st.divider()
    st.subheader("On-Demand Tests")
    # Buttons set state flags; we run tests later to avoid autorefresh interference
    dns_host = st.text_input("DNS test hostname", value="www.google.com")
    dns_server = st.text_input("DNS resolver IP (optional)", value="")
    if st.button("Run DNS latency test"):
        state.ops["dns"]["start"] = True
        state.ops["dns"]["args"] = {"host": dns_host, "resolver": (dns_server or None)}
    if st.button("Run Bandwidth (Speedtest)"):
        state.ops["speed"]["start"] = True
    host_to_trace = st.text_input("Traceroute target", value="8.8.8.8")
    if st.button("Run Traceroute"):
        state.ops["trace"]["start"] = True
        state.ops["trace"]["args"] = {"host": host_to_trace}

    st.divider()
    st.subheader("CSV Logging")
    enable_log = st.checkbox("Enable CSV logging", value=state.logging["enabled"])
    log_dir = st.text_input("Log directory", value=state.logging["dir"])
    if enable_log != state.logging["enabled"] or log_dir != state.logging["dir"]:
        state.logging["enabled"] = enable_log
        state.logging["dir"] = log_dir
        if enable_log:
            ensure_log_files(state)

# Disable autorefresh while a one-off operation is running to prevent "page reset"
busy = state.ops["dns"]["start"] or state.ops["speed"]["start"] or state.ops["trace"]["start"]
if not busy:
    try:
        from streamlit_autorefresh import st_autorefresh
        st_autorefresh(interval=state.refresh_ms, key="auto-r")
    except Exception:
        pass

# Build manual targets list
manual_targets = [t.strip() for t in targets_text.splitlines() if t.strip()]

# Rank endpoints from sampler and apply stickiness
state.sampler.min_seen = int(min_snap)
port_filter = make_port_filter(port_spec) if port_spec.strip() else None
ranked = state.sampler.rank_endpoints(port_filter=port_filter, include_private=include_private)

# Update sticky map expiries for the current top endpoints
now_s = now_ts()
if enable_auto:
    for r in ranked[:int(top_n)]:
        ip = r["ip"]
        expiry = now_s + stickiness_secs
        prev = state.sticky.get(ip, 0)
        if expiry > prev:
            state.sticky[ip] = expiry

# Gather current sticky set (not expired)
sticky_set = {ip for ip, exp in state.sticky.items() if exp > now_s}

# Compose auto target list
auto_targets = list(sticky_set) if enable_auto else []
state.auto_targets = auto_targets

# Desired monitor set
if replace_manual and enable_auto:
    desired_targets = auto_targets
else:
    desired_targets = manual_targets + [t for t in auto_targets if t not in manual_targets]

# Reconcile monitors
existing = set(state.monitors.keys())
for host in list(existing - set(desired_targets)):
    state.monitors[host].stop()
    del state.monitors[host]

for host in desired_targets:
    if host not in state.monitors:
        state.monitors[host] = PingMonitor(host, interval_ms=interval_ms, window=window)
    else:
        mon = state.monitors[host]
        mon.interval_ms = interval_ms
        if mon.window != window:
            mon.window = window
            mon.samples = deque(mon.samples, maxlen=window)
            mon.timestamps = deque(mon.timestamps, maxlen=window)

# Start/stop polling
with st.sidebar:
    colb = st.columns(2)
    with colb[0]:
        if st.button("▶ Start Monitoring", use_container_width=True):
            state.running = True
    with colb[1]:
        if st.button("⏹ Stop", use_container_width=True):
            state.running = False

if state.running:
    for mon in state.monitors.values():
        mon.start()
else:
    for mon in state.monitors.values():
        mon.stop()

# Top status
top_cols = st.columns([1,1,1,1,1])
wifi = None
def wifi_status():
    try:
        sysname = platform.system()
        if sysname == "Windows":
            out = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True, timeout=3)
            s = out.stdout
            if "State" in s and "connected" in s.lower():
                ssid = re.search(r"^\s*SSID\s*:\s*(.+)$", s, re.M)
                sig  = re.search(r"^\s*Signal\s*:\s*(\d+)%", s, re.M)
                return {"ssid": ssid.group(1).strip() if ssid else None, "signal_percent": int(sig.group(1)) if sig else None}
        elif sysname == "Linux":
            try:
                out = subprocess.run(["nmcli", "-t", "-f", "ACTIVE,SSID,SIGNAL", "dev", "wifi"], capture_output=True, text=True, timeout=3)
                for line in out.stdout.splitlines():
                    parts = line.strip().split(":")
                    if len(parts) >= 3 and parts[0] == "yes":
                        return {"ssid": parts[1], "signal_percent": int(parts[2])}
            except Exception:
                pass
        elif sysname == "Darwin":
            airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
            if os.path.exists(airport):
                out = subprocess.run([airport, "-I"], capture_output=True, text=True, timeout=3)
                s = out.stdout
                ssid = re.search(r"^\s*SSID:\s*(.+)$", s, re.M)
                rssi = re.search(r"^\s*agrCtlRSSI:\s*(-?\d+)", s, re.M)
                pct = None
                if rssi:
                    rssi_val = int(rssi.group(1))
                    pct = int(np.clip((rssi_val + 90) * (100/60), 0, 100))
                return {"ssid": ssid.group(1).strip() if ssid else None, "signal_percent": pct}
    except Exception:
        pass
    return None
try:
    wifi = wifi_status()
except Exception:
    wifi = None

with top_cols[0]:
    st.metric("Local Gateway", gw)
with top_cols[1]:
    st.metric("Wi-Fi (SSID)", (wifi or {}).get("ssid","N/A"))
with top_cols[2]:
    st.metric("Wi-Fi Signal", f"{(wifi or {}).get('signal_percent','N/A')}%")
# Throughput hints
th = throughput_hints_tick(state) if psutil else {"error":"psutil not installed"}
iface_rates = th.get("iface_rates", {})
total_rx = sum(v["rx_Bps"] for v in iface_rates.values()) if iface_rates else 0.0
total_tx = sum(v["tx_Bps"] for v in iface_rates.values()) if iface_rates else 0.0
with top_cols[3]:
    st.metric("Throughput RX", bytes_per_sec_to_human(total_rx))
with top_cols[4]:
    st.metric("Throughput TX", bytes_per_sec_to_human(total_tx))

# Auto-discovered endpoints table
st.divider()
st.subheader("Auto-Discovered Active Endpoints (sticky included)")
if not psutil:
    st.warning("psutil is not installed; auto-discovery is unavailable. Install `psutil` to enable this feature.")
else:
    display = []
    # Build merged view of sticky + ranked top 20
    merged = {r["ip"]: r for r in ranked[:20]}
    for ip in list(sticky_set):
        merged.setdefault(ip, {"ip": ip, "ports": [], "score": 0, "seen": 0, "cur_conns": 0, "age_sec": 0})
    for ip, r in merged.items():
        host = rdns_lookup(ip)
        procnames = ", ".join(pid_names(tuple(r.get("pids", [])))) if r.get("pids") else ""
        display.append({
            "IP": ip,
            "Host (rDNS)": host,
            "Ports": ",".join(str(p) for p in r.get("ports", [])[:8]) + ("…" if len(r.get("ports", []))>8 else ""),
            "Score": f"{r.get('score',0):.1f}",
            "Seen": r.get("seen", 0),
            "Curr Conns": r.get("cur_conns", 0),
            "Sticky (min left)": f"{max(0,int((state.sticky.get(ip,0)-now_ts())/60))}" if ip in sticky_set else "0",
            "Monitored": "✅" if ip in state.monitors else "—",
        })
    if display:
        st.dataframe(pd.DataFrame(display), use_container_width=True, hide_index=True)
        if state.logging["enabled"]:
            ensure_log_files(state)
            log_discover_rows(state, list(ranked[:20]))
    else:
        st.info("No endpoints met the selection criteria yet. Start the game and let auto-discover watch for a minute.")

# Metrics & charts + logging
st.divider()
targets = list(state.monitors.keys())
if not targets:
    st.info("No monitors active. Enable auto-discovery or add manual targets, then click **Start Monitoring**.")
else:
    grid = st.columns(2)
    left_hosts = targets[::2]
    right_hosts = targets[1::2]

    def render_host_panel(host, col):
        mon = state.monitors[host]
        with col:
            st.subheader(host)
            m = mon.metrics()
            met_cols = st.columns(5)
            met_cols[0].metric("Avg (ms)", f"{m['avg_ms']:.1f}" if m['avg_ms'] is not None else "—")
            met_cols[1].metric("Jitter (ms)", f"{m['jitter_ms']:.1f}")
            met_cols[2].metric("p95 (ms)", f"{m['p95_ms']:.1f}" if m['p95_ms'] is not None else "—")
            met_cols[3].metric("Worst (ms)", f"{m['worst_ms']:.1f}" if m['worst_ms'] is not None else "—")
            met_cols[4].metric("Loss (recent)", f"{m['loss_recent_pct']:.1f}%")
            if mon.timestamps:
                df = pd.DataFrame({
                    "time": [datetime.fromtimestamp(ts) for ts in mon.timestamps],
                    "latency_ms": [v if v is not None else np.nan for v in mon.samples],
                }).set_index("time")
                st.line_chart(df, height=160, use_container_width=True)
            else:
                st.info("No samples yet. Click **Start Monitoring**.")
            # Logging
            if state.logging["enabled"]:
                ensure_log_files(state)
                log_metrics_row(state, host, m)

    for h in left_hosts:
        render_host_panel(h, grid[0])
    for h in right_hosts:
        render_host_panel(h, grid[1])

# ------------------ Handle on-demand tests (stateful, rerun-safe) ------------------
# DNS test
if state.ops["dns"]["start"]:
    args = state.ops["dns"]["args"] or {}
    st.info(f"Running DNS latency test for **{args.get('host','')}** via **{args.get('resolver','system default')}**…")
    if dns is None:
        st.error("dnspython not installed. Add `dnspython` to requirements to use DNS test.")
    else:
        try:
            res = dns.resolver.Resolver(configure=True)
            if args.get("resolver"):
                res.nameservers = [args["resolver"]]
            res.timeout = 2.0
            res.lifetime = 2.0
            vals = []
            attempts = 5
            for _ in range(attempts):
                t0 = time.perf_counter()
                try:
                    _ = res.resolve(args.get("host","www.google.com"), "A")
                    ms = (time.perf_counter() - t0) * 1000.0
                    vals.append(ms)
                except Exception:
                    vals.append(None)
            state.ops["dns"]["result"] = vals
        except Exception as e:
            state.ops["dns"]["result"] = f"Error: {e}"
    state.ops["dns"]["start"] = False

if state.ops["dns"]["result"] is not None:
    vals = state.ops["dns"]["result"]
    if isinstance(vals, list):
        good = [v for v in vals if v is not None]
        st.subheader("DNS Latency Results")
        if good:
            st.write(f"Avg: {np.mean(good):.1f} ms • p95: {np.percentile(good,95):.1f} ms • failures: {vals.count(None)} / {len(vals)}")
            df = pd.DataFrame({"attempt": list(range(1, len(vals)+1)), "ms": [v if v is not None else np.nan for v in vals]}).set_index("attempt")
            st.bar_chart(df, height=160, use_container_width=True)
        else:
            st.warning("All attempts failed.")
    else:
        st.error(vals)

# Speedtest
if state.ops["speed"]["start"]:
    st.info("Running bandwidth test (download/upload/ping)…")
    if speedtest is None:
        state.ops["speed"]["result"] = "speedtest-cli not installed. Add `speedtest-cli` to requirements."
    else:
        try:
            stc = speedtest.Speedtest(secure=True)
            stc.get_servers([])
            stc.get_best_server()
            dl = stc.download() / 1e6  # Mbps
            ul = stc.upload() / 1e6    # Mbps
            ping_ms = stc.results.ping
            srv = stc.results.server
            state.ops["speed"]["result"] = {"dl": dl, "ul": ul, "ping_ms": ping_ms, "srv": srv}
        except Exception as e:
            state.ops["speed"]["result"] = f"Speedtest failed: {e}"
    state.ops["speed"]["start"] = False

if state.ops["speed"]["result"] is not None:
    r = state.ops["speed"]["result"]
    st.subheader("Bandwidth Result")
    if isinstance(r, dict):
        st.success(f"Download {r['dl']:.1f} Mbps • Upload {r['ul']:.1f} Mbps • Latency {r['ping_ms']:.1f} ms")
        st.caption(f"Server: {r['srv'].get('name','N/A')} ({r['srv'].get('sponsor','')}) — {r['srv'].get('country','')}")
    else:
        st.error(r)

# Traceroute
if state.ops["trace"]["start"]:
    host = (state.ops["trace"]["args"] or {}).get("host","8.8.8.8")
    st.info(f"Tracing route to {host}…")
    sysname = platform.system()
    if sysname == "Windows":
        cmd = ["tracert","-d","-h","24",host]
    else:
        cmd = ["traceroute","-n","-m","24",host]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        state.ops["trace"]["result"] = proc.stdout
    except Exception as e:
        state.ops["trace"]["result"] = f"Traceroute failed: {e}"
    state.ops["trace"]["start"] = False

if state.ops["trace"]["result"] is not None:
    st.subheader("Traceroute Output")
    st.text_area("Output", value=state.ops["trace"]["result"], height=260)

# Diagnosis
st.divider()
st.subheader("Quick Diagnosis (Heuristic)")
diag = []
gw_host = gw
if gw_host in state.monitors:
    gwm = state.monitors[gw_host].metrics()
    if gwm["avg_ms"] is not None and gwm["avg_ms"] > 20:
        diag.append("High latency to the router. Suspect Wi‑Fi/interference or local congestion.")
    if gwm["loss_recent_pct"] > 1.0:
        diag.append("Packet loss to the router. Likely Wi‑Fi issues or bad cabling.")

internet_targets = [t for t in state.monitors.keys() if t != gw_host]
if internet_targets:
    best = None
    best_ms = float("inf")
    for t in internet_targets:
        m = state.monitors[t].metrics()
        if m["avg_ms"] is not None and m["avg_ms"] < best_ms:
            best_ms = m["avg_ms"]; best = (t, m)
    if best and best[1]["avg_ms"] is not None:
        if (gwm.get("avg_ms") or 0) < 10 and best[1]["avg_ms"] > 60:
            diag.append(f"Router looks fine, but {best[0]} is high latency. Likely ISP/backhaul or distant server.")
        if best[1]["jitter_ms"] > 20:
            diag.append(f"Jitter > 20 ms on {best[0]}. Real-time games will feel spiky.")

if not diag:
    st.success("No obvious local red flags. If gameplay still feels bad, try DNS test or traceroute to your game's region/server.")
else:
    for d in diag:
        st.warning(d)

st.caption("© 2025 — Uses OS ping, system connection tables, and optional OS tools (ss/nettop/netstat).")
