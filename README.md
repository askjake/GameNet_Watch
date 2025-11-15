# GameNet Watch — Auto-Discover Edition

This build adds **Auto-Discover** to the original GameNet Watch:
- Samples your OS connection table (via `psutil`) every ~2s.
- Ranks remote endpoints by **persistence** and **fan‑out** (how many simultaneous sockets).
- (Optional) **Port filtering** (e.g., `3074, 27015-27050, 3478-3480`) to focus on game traffic.
- Automatically **adds the top N endpoints** to the ping monitors (augment or replace your manual list).

No admin rights and no packet capture needed.

## Quick start
```
python -m venv .venv
# activate it...
pip install -r requirements.txt
streamlit run app.py
```

## Notes
- Discovery is heuristic — game servers/CDNs often use rotating IPs. Increase **Minimum snapshots** to reduce flapping.
- UDP flows may show as connected with `status=NONE`; we include them when they have a remote endpoint.
- Reverse DNS and process names are best-effort and cached briefly.
