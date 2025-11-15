# netwatch_gaming/app.py
import os
import re
import sys
import time
import math
import json
import queue
import threading
import platform
import subprocess
from collections import deque
from datetime import datetime

import numpy as np
import pandas as pd
import streamlit as st

# Optional deps guarded by try/except to keep the app resilient
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
    import psutil  # for system stats and optional Wi-Fi on some platforms
except Exception:
    psutil = None

# --- App meta ---
APP_TITLE = "GameNet Watch — Real‑time Network Monitor"
APP_VER = "1.0.0"

# --- Utilities ---
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
    # Fallback: try parsing OS route table
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
    # Windows localized fallback — parse "Average = Xms" if single probe still reported
    m = re.search(r"average\s*=\s*([\d\.]+)\s*ms", s)
    if m:
        return float(m.group(1))
    # macOS alternative "round-trip min/avg/max/stddev = X/Y/Z/W ms" (single probe not present)
    m = re.search(r"round-trip.*=\s*[\d\.]+/([\d\.]+)/", s)
    if m:
        try:
            return float(m.group(1))
        except:
            return None
    return None

def ping_once(host: str, timeout_ms: int = 1000):
    """Returns latency in ms (float) or None on timeout/error. Uses system ping for privilege-free ICMP."""
    if platform.system() == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
    else:
        # -c 1 single probe; rely on subprocess timeout instead of per-ping timeout for portability
        cmd = ["ping", "-c", "1", host]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=max(1.0, timeout_ms/1000.0 + 0.5))
        if proc.returncode == 0:
            return parse_ping_ms(proc.stdout)
        else:
            # Some pings return non-zero on loss; still try parsing any time value that may appear
            ms = parse_ping_ms(proc.stdout)
            return ms
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None

def calc_jitter_mean_abs_diffs(values):
    """RTP-style rough jitter: mean absolute delta between consecutive samples (ignoring None)."""
    vals = [v for v in values if v is not None]
    if len(vals) < 2:
        return 0.0
    diffs = [abs(vals[i] - vals[i-1]) for i in range(1, len(vals))]
    return float(sum(diffs) / len(diffs))

def wifi_status():
    """Best-effort Wi‑Fi signal/SSID on common platforms. Returns dict or None."""
    try:
        sysname = platform.system()
        if sysname == "Windows":
            out = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True, timeout=3)
            s = out.stdout
            if "State" in s and "connected" in s.lower():
                ssid = re.search(r"^\s*SSID\s*:\s*(.+)$", s, re.M)
                sig  = re.search(r"^\s*Signal\s*:\s*(\d+)%", s, re.M)
                bssid = re.search(r"^\s*BSSID\s*:\s*(.+)$", s, re.M)
                radio = re.search(r"^\s*Radio type\s*:\s*(.+)$", s, re.M)
                chan  = re.search(r"^\s*Channel\s*:\s*(.+)$", s, re.M)
                return {
                    "ssid": ssid.group(1).strip() if ssid else None,
                    "signal_percent": int(sig.group(1)) if sig else None,
                    "bssid": bssid.group(1).strip() if bssid else None,
                    "radio": radio.group(1).strip() if radio else None,
                    "channel": chan.group(1).strip() if chan else None,
                }
        elif sysname == "Linux":
            # Prefer nmcli if present
            try:
                out = subprocess.run(["nmcli", "-t", "-f", "ACTIVE,SSID,SIGNAL", "dev", "wifi"], capture_output=True, text=True, timeout=3)
                for line in out.stdout.splitlines():
                    parts = line.strip().split(":")
                    if len(parts) >= 3 and parts[0] == "yes":
                        return {"ssid": parts[1], "signal_percent": int(parts[2])}
            except Exception:
                pass
            # Try iwconfig
            out = subprocess.run(["iwconfig"], capture_output=True, text=True, timeout=3)
            s = out.stdout
            ssid = re.search(r'ESSID:"([^"]+)"', s)
            qual = re.search(r"Link Quality=(\d+)/(\d+)", s)
            if qual:
                q = int(qual.group(1)); maxq = int(qual.group(2))
                pct = int(100.0 * q / maxq) if maxq else None
            else:
                pct = None
            if ssid or pct is not None:
                return {"ssid": ssid.group(1) if ssid else None, "signal_percent": pct}
        elif sysname == "Darwin":
            airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
            if os.path.exists(airport):
                out = subprocess.run([airport, "-I"], capture_output=True, text=True, timeout=3)
                s = out.stdout
                ssid = re.search(r"^\s*SSID:\s*(.+)$", s, re.M)
                rssi = re.search(r"^\s*agrCtlRSSI:\s*(-?\d+)", s, re.M)
                ch   = re.search(r"^\s*channel:\s*(.+)$", s, re.M)
                # Convert RSSI dBm to rough percent scale
                pct = None
                if rssi:
                    rssi_val = int(rssi.group(1))
                    # Map -90..-30 dBm to 0..100%
                    pct = int(np.clip((rssi_val + 90) * (100/60), 0, 100))
                return {"ssid": ssid.group(1).strip() if ssid else None, "signal_percent": pct, "channel": ch.group(1).strip() if ch else None}
    except Exception:
        pass
    return None

def dns_lookup_latency(hostname: str, resolver_ip: str = None, attempts: int = 3, timeout: float = 2.0):
    """Returns list of ms timings for DNS A-record lookups, or [] on failure/no dnspython."""
    results = []
    if dns is None:
        return results
    try:
        res = dns.resolver.Resolver(configure=True)
        if resolver_ip:
            res.nameservers = [resolver_ip]
        res.timeout = timeout
        res.lifetime = timeout
        for _ in range(attempts):
            t0 = time.perf_counter()
            try:
                _ = res.resolve(hostname, "A")
                ms = (time.perf_counter() - t0) * 1000.0
                results.append(ms)
            except Exception:
                results.append(None)
        return results
    except Exception:
        return results

def run_traceroute(host: str, max_hops: int = 20):
    sysname = platform.system()
    if sysname == "Windows":
        cmd = ["tracert", "-d", "-h", str(max_hops), host]
    else:
        cmd = ["traceroute", "-n", "-m", str(max_hops), host]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return proc.stdout
    except Exception as e:
        return f"Traceroute failed: {e}"

# --- Ping monitor worker ---
class PingMonitor:
    def __init__(self, host: str, interval_ms: int = 1000, window: int = 120):
        self.host = host
        self.interval_ms = interval_ms
        self.window = window
        self.samples = deque(maxlen=window)  # floats (ms) or None
        self.timestamps = deque(maxlen=window)  # unix ts
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
            self.timestamps.append(time.time())
            # Sleep remainder of interval
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

# --- Streamlit state helpers ---
def get_state():
    if "monitors" not in st.session_state:
        st.session_state.monitors = {}
    if "running" not in st.session_state:
        st.session_state.running = False
    if "history" not in st.session_state:
        st.session_state.history = {}  # host -> list of (ts, ms)
    if "refresh_ms" not in st.session_state:
        st.session_state.refresh_ms = 1000
    return st.session_state

# --- UI ---
st.set_page_config(page_title=APP_TITLE, layout="wide")
st.title(APP_TITLE)
st.caption(f"v{APP_VER} — Built for low-latency gaming visibility (latency, jitter, loss, DNS, bandwidth, and path).")
state = get_state()

# Autorefresh if available
try:
    from streamlit_autorefresh import st_autorefresh
    st_autorefresh(interval=state.refresh_ms, key="auto-r")
except Exception:
    pass

with st.sidebar:
    st.header("Targets & Settings")
    gw = default_gateway_v4()
    default_targets = [gw, "1.1.1.1", "8.8.8.8", "www.google.com"]
    targets_text = st.text_area(
        "Ping targets (one per line: IP or hostname)",
        value="\n".join(default_targets),
        height=120,
        help="Include your router/gateway, a public DNS (1.1.1.1 / 8.8.8.8), and the game server/domain if known.",
    )
    interval_ms = st.slider("Ping interval (ms)", min_value=200, max_value=2000, value=1000, step=100)
    window = st.slider("Sliding window size (samples)", min_value=30, max_value=600, value=180, step=30)
    state.refresh_ms = st.slider("UI refresh (ms)", min_value=500, max_value=5000, value=1000, step=500)

    colb = st.columns(2)
    with colb[0]:
        if st.button("▶ Start Monitoring", use_container_width=True):
            state.running = True
    with colb[1]:
        if st.button("⏹ Stop", use_container_width=True):
            state.running = False

    st.divider()
    st.subheader("On‑Demand Tests")
    dns_host = st.text_input("DNS test hostname", value="www.google.com")
    dns_server = st.text_input("DNS resolver IP (optional)", value="")
    run_dns = st.button("Run DNS latency test")
    run_speed = st.button("Run Bandwidth (Speedtest)")
    host_to_trace = st.text_input("Traceroute target", value="8.8.8.8")
    run_trace = st.button("Run Traceroute")
    st.caption("Speedtest may disrupt gaming; prefer to run when idle. Traceroute helps locate path bottlenecks.")

# Start/stop monitors per current targets
targets = [t.strip() for t in targets_text.splitlines() if t.strip()]
existing = set(state.monitors.keys())

# Stop removed
for host in list(existing - set(targets)):
    state.monitors[host].stop()
    del state.monitors[host]

# Create or update existing monitors
for host in targets:
    if host not in state.monitors:
        state.monitors[host] = PingMonitor(host, interval_ms=interval_ms, window=window)
    else:
        # Update parameters
        mon = state.monitors[host]
        mon.interval_ms = interval_ms
        mon.window = window
        mon.samples = deque(mon.samples, maxlen=window)
        mon.timestamps = deque(mon.timestamps, maxlen=window)

# Control run state
if state.running:
    for mon in state.monitors.values():
        mon.start()
else:
    for mon in state.monitors.values():
        mon.stop()

# Top status row
top_cols = st.columns([1,1,1,1])
wifi = wifi_status()
with top_cols[0]:
    st.metric("Local Gateway", gw)
with top_cols[1]:
    if wifi:
        st.metric("Wi‑Fi (SSID)", wifi.get("ssid", "N/A"))
    else:
        st.metric("Wi‑Fi", "N/A")
with top_cols[2]:
    if wifi and wifi.get("signal_percent") is not None:
        st.metric("Wi‑Fi Signal", f"{wifi['signal_percent']}%")
    else:
        st.metric("Wi‑Fi Signal", "N/A")
with top_cols[3]:
    st.metric("Monitors Running", sum(1 for m in state.monitors.values() if m._thread and m._thread.is_alive()))

st.divider()

# Metrics & charts
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

        # Build dataframe for chart from current samples
        if mon.timestamps:
            df = pd.DataFrame({
                "time": [datetime.fromtimestamp(ts) for ts in mon.timestamps],
                "latency_ms": [v if v is not None else np.nan for v in mon.samples],
            }).set_index("time")
            st.line_chart(df, height=160, use_container_width=True)
        else:
            st.info("No samples yet. Click **Start Monitoring**.")

for h in left_hosts:
    render_host_panel(h, grid[0])
for h in right_hosts:
    render_host_panel(h, grid[1])

st.divider()

# DNS test
if run_dns:
    if dns is None:
        st.error("dnspython not installed. Add `dnspython` to requirements to use DNS test.")
    else:
        with st.spinner("Running DNS latency test…"):
            results = dns_lookup_latency(dns_host, resolver_ip=dns_server or None, attempts=5, timeout=2.0)
        vals = [v for v in results if v is not None]
        st.write(f"DNS lookups for **{dns_host}** via **{dns_server or 'system default'}**:")
        if vals:
            st.write(f"• Avg: {np.mean(vals):.1f} ms, p95: {np.percentile(vals,95):.1f} ms, attempts: {len(results)}, failures: {results.count(None)}")
            df = pd.DataFrame({"attempt": list(range(1, len(results)+1)), "ms": [v if v is not None else np.nan for v in results]}).set_index("attempt")
            st.bar_chart(df, height=160, use_container_width=True)
        else:
            st.warning("All attempts failed. Resolver may be unreachable or blocked.")

# Speedtest
if run_speed:
    if speedtest is None:
        st.error("speedtest-cli not installed. Add `speedtest-cli` to requirements to use Bandwidth test.")
    else:
        with st.spinner("Running bandwidth test (download/upload/ping)…"):
            try:
                stc = speedtest.Speedtest(secure=True)
                stc.get_servers([])
                stc.get_best_server()
                dl = stc.download() / 1e6  # Mbps
                ul = stc.upload() / 1e6    # Mbps
                ping_ms = stc.results.ping
                srv = stc.results.server
                st.success(f"Download {dl:.1f} Mbps • Upload {ul:.1f} Mbps • Latency {ping_ms:.1f} ms")
                st.caption(f"Server: {srv.get('name', 'N/A')} ({srv.get('sponsor','')}) — {srv.get('country','')}")
            except Exception as e:
                st.error(f"Speedtest failed: {e}")

# Traceroute
if run_trace:
    with st.spinner(f"Tracing route to {host_to_trace}…"):
        trace = run_traceroute(host_to_trace, max_hops=24)
    st.text_area("Traceroute output", value=trace, height=260)

# Heuristic diagnosis
st.subheader("Quick Diagnosis (Heuristic)")
st.caption("Rules of thumb to spot likely culprits.")
diag = []
gw_host = gw
if gw_host in state.monitors:
    gwm = state.monitors[gw_host].metrics()
    if gwm["avg_ms"] is not None and gwm["avg_ms"] > 20:
        diag.append("High latency to the router (gateway). Suspect **Wi‑Fi signal/interference** or **local congestion**.")
    if gwm["loss_recent_pct"] > 1.0:
        diag.append("Packet loss to the router. Likely **Wi‑Fi** issues or **bad cabling**.")

internet_targets = [t for t in targets if t not in (gw_host,)]
if internet_targets:
    # pick the 'best' internet target for diagnosis
    best = None
    best_ms = float("inf")
    for t in internet_targets:
        m = state.monitors[t].metrics()
        if m["avg_ms"] is not None and m["avg_ms"] < best_ms:
            best_ms = m["avg_ms"]; best = (t, m)
    if best and best[1]["avg_ms"] is not None:
        if (gwm.get("avg_ms") or 0) < 10 and best[1]["avg_ms"] > 60:
            diag.append(f"Router looks fine, but **{best[0]}** is high latency. Likely **ISP/backhaul** or **far server**.")
        if best[1]["jitter_ms"] > 20:
            diag.append(f"Jitter > 20 ms on **{best[0]}**. Real‑time games will feel spiky.")

if not diag:
    st.success("No obvious local red flags. If gameplay still feels bad, try DNS test or traceroute to your game's region/server.")
else:
    for d in diag:
        st.warning(d)

st.divider()
with st.expander("Tips"):
    st.markdown("""
- **Keep pings conservative (≥ 500 ms interval)** while gaming to avoid stealing CPU/network from the game.
- For Wi‑Fi: aim for **≥ 70%** signal. If lower, try 5 GHz (or 6 GHz) and minimize obstructions.
- Packet loss **> 1%** hurts most shooters; jitter **> 20 ms** often feels like 'rubber-banding'.
- If gateway is stable but 'Internet' isn't, call the ISP or try a different DNS (1.1.1.1 / 8.8.8.8).
- Use **Traceroute** to see where latency jumps—home, ISP edge, or distant hop.
""")

st.caption("© 2025 — This tool runs simple ICMP pings and standard DNS/speed tests. Use responsibly.")
