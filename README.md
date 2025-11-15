# GameNet Watch — v1.4 Auto‑Discover + Stickiness + Throughput Hints + CSV Logs

**What's new (and fixes):**
- **Buttons not working under autorefresh** → fixed. One‑off tests (DNS, Speedtest, Traceroute) are now stateful and temporarily **pause autorefresh** so results render reliably.
- **Auto‑Discover stickiness**: game servers you hit are kept in the monitor set for **X minutes** even if they temporarily drop out.
- **Throughput hints**:
  - Cross‑platform interface rates via psutil deltas.
  - Linux: parses `ss -tin` for median **RTT**/**cwnd**, rough BDP/throughput.
  - macOS: tries `nettop -P -L 1 -x` for observed bytes in/out.
  - Windows: supplements with `netstat -e` totals.
- **CSV logging**:
  - `metrics_*.csv`: timestamped per‑target latency/jitter/loss metrics.
  - `discover_*.csv`: snapshots of auto‑discovered endpoints.

## Quick start
```
python -m venv .venv
# activate it...
pip install -r requirements.txt
streamlit run app.py
```

## Tips
- Use **Stickiness (minutes)** to keep a server in view during a whole match.
- Keep **ping interval ≥ 500 ms** while gaming to avoid unnecessary load.
- Use **port filter** to focus auto‑discover on game ports (e.g., 3074, 27015‑27050, 3478‑3480).

Logs default to a `logs/` folder under your working directory. Change it in the sidebar.
