# GameNet Watch — Real‑time Network Monitor for Gaming

A self‑contained Streamlit app you can run alongside games to track the metrics that matter most for online play:

- **Latency** (per‑target)
- **Jitter** (mean absolute change between pings)
- **Packet loss**
- **DNS lookup latency** (optional)
- **Bandwidth test** (optional, via speedtest-cli)
- **Traceroute** (path visibility)
- **Wi‑Fi signal snapshot** (Windows, Linux, macOS best‑effort)

## Quick start

### 1) Install Python 3.10+
Windows/Mac/Linux all supported.

### 2) Create a venv (recommended)
```bash
python -m venv .venv
# Windows
.\.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate
```

### 3) Install dependencies
```bash
pip install -r requirements.txt
```

### 4) Run the app
```bash
streamlit run app.py
```

Open the local URL that Streamlit prints (e.g., http://localhost:8501).

## Using the app

- Put your **router/gateway**, **public DNS (1.1.1.1, 8.8.8.8)**, and **game server/domain** into the sidebar list.  
- Click **Start Monitoring** to begin.  
- Use **DNS**, **Speedtest**, and **Traceroute** on demand. *(Speed tests can disrupt gameplay — run when idle!)*

## Notes

- ICMP pings use your OS `ping` command (no admin privileges required).  
- Wi‑Fi details are best‑effort and may show **N/A** on some setups.  
- Jitter is computed as the mean absolute difference between consecutive latency samples (RTP‑style rough estimate).  
- If you see high latency to the **gateway**, it’s likely **Wi‑Fi or cabling**. If gateway is fine but public hosts aren’t, it’s likely **ISP/backhaul** or **distant server**.

## License
Personal use permitted. No warranty. Use responsibly.
