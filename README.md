# Sentinel-X

**An AI-Powered Cyber Attack Investigation Platform** — a lightweight, host-based intrusion detection system (HIDS) that watches a single machine in real time, correlates activity across multiple sources, and generates human-readable incident reports.

Built as a B.Tech minor project (Cybersecurity specialization).

---

## What It Does

Sentinel-X runs four independent monitoring collectors simultaneously, each watching a different aspect of the host system, and records everything it finds into a single, structured event database:

| Collector | What it watches | How |
|---|---|---|
| **Process Monitor** | New/terminated processes | Snapshot-diffing via `psutil`, filtered against a configurable ignore list |
| **File Integrity Monitor** | File create/modify/delete events | Real-time OS-level notifications via `watchdog`, with debouncing and SHA-256 hash verification to confirm genuine content changes |
| **USB Detector** | USB drive insertion | Snapshot-diffing of mounted drive letters |
| **Login/Auth Monitor** | Login attempts, brute-force patterns | Windows Security Event Log (`pywin32`), with sliding-window brute-force detection (5 failures within 60 seconds triggers a high-severity alert) |

Every collector emits the same universal `Event` structure into a shared SQLite database, regardless of what it's watching — this is the core architectural decision behind the whole project: **collectors never know about storage or analysis, they only produce structured evidence.**

A lightweight **Timeline Engine** then correlates events across all four collectors by time proximity, grouping related activity into clusters and automatically flagging the ones worth investigating — either because they involve an elevated-severity event, or because multiple independent collectors fired close together (a stronger signal than any single collector acting alone).

A CLI reporting script ties it together: total events, breakdown by source and severity, high-priority alerts, and the flagged activity clusters.

---

## Architecture

```
sentinel-x/
├── src/
│   ├── core/
│   │   ├── config.py        # Fail-closed YAML configuration loader
│   │   ├── exceptions.py    # Custom exception hierarchy
│   │   ├── logger.py        # Rotating file logger
│   │   └── models.py        # Event dataclass — the shared schema every collector uses
│   ├── collectors/
│   │   ├── process_monitor.py
│   │   ├── file_monitor.py
│   │   ├── usb_monitor.py
│   │   └── login_monitor.py
│   ├── engine/
│   │   └── timeline_engine.py   # Time-window event clustering and correlation flagging
│   └── storage/
│       ├── database.py      # SQLite schema + connection setup
│       └── repository.py    # insert_event() / query_events() — parameterized queries only
├── config/default.yaml
├── tests/                    # pytest suite, 21 tests
├── run_all.py                 # Starts all four collectors concurrently (the live demo)
├── report.py                   # Generates a readable, correlated incident report
└── requirements.txt
```

**Key design decisions:**
- **Fail-closed configuration** — the app refuses to start rather than silently running with missing or malformed settings.
- **Parameterized SQL everywhere** — no string-built queries, eliminating SQL injection as a possibility by construction.
- **Debouncing and hash verification** in file monitoring, since a single file save can trigger multiple raw OS events, and not every OS notification means content genuinely changed.
- **Sliding-window brute-force detection** for login monitoring — counts failures within a rolling time window rather than a simple total, so slow, spread-out failures don't trigger false positives.
- **Time-window clustering** in the Timeline Engine — events within a configurable gap of the *most recently clustered* event (not the cluster's first event) join the same group, so a continuous burst of activity isn't artificially split apart just because its total span exceeds the gap threshold.
- **Correlation-aware flagging** — a cluster is marked noteworthy if it contains an elevated-severity event, or if three or more distinct collectors fired within the same window. The second condition exists specifically because routine background activity (e.g. a login triggering a couple of process spawns) commonly involves two collectors; requiring three filters that out while still catching genuinely cross-source incidents.

---

## Installation

Requires Python 3.10+ on Windows (the login and process monitors use Windows-specific APIs).

```powershell
git clone https://github.com/Yaxex28/Sentinel-X.git
cd Sentinel-X
pip install -r requirements.txt
```

---

## Running It

**Login monitoring requires Administrator privileges** (Windows restricts read access to the Security Event Log). Run PowerShell as Administrator for the full demo.

**Start all four collectors together:**
```powershell
python run_all.py
```
This watches live system activity — open a program, plug in a USB, or edit a file in `watch_test/` to generate events. Press `Ctrl+C` to stop.

**Generate a correlated incident report from what was collected:**
```powershell
python report.py
```
Prints total events, a breakdown by source and severity, all medium/high-severity alerts, and the Timeline Engine's clustered activity view with flagged incidents highlighted.

**Run the test suite:**
```powershell
python -m pytest -v
```

---

## Configuration

`config/default.yaml` controls collector behavior — poll intervals, the process ignore list, and watched file paths. `run_all.py` reads these values directly rather than hardcoding them, so changing the YAML changes runtime behavior without touching code:

```yaml
monitoring:
  process:
    poll_interval_seconds: 5
    ignore_list: [svchost.exe, explorer.exe]
  file_integrity:
    watched_paths: [watch_test]
  usb:
    auto_scan_on_insert: false
```

---

## Testing

21 automated tests via `pytest`, covering:
- Fail-closed config validation (missing files, missing required keys)
- Storage round-trips and filtered queries, using isolated in-memory SQLite per test
- File hashing determinism and debouncing timing
- USB drive-diffing logic
- Brute-force sliding-window detection — the negative case (spread-out failures, correctly not triggering), the positive case (rapid failures, correctly triggering), and a boundary test at exactly the window edge
- Timeline clustering (correct grouping across a time gap) and correlation flagging (elevated severity vs. multi-source routine activity)

---

## Honest Scope and Positioning

Sentinel-X does **not** claim algorithmic novelty. Multi-source event correlation combined with AI-generated incident narratives is an active area of security research (e.g., GenDFIR, which uses retrieval-augmented LLMs for forensic timeline reconstruction). What Sentinel-X offers instead is a **working, live, real-time, single-machine implementation** of the core idea — structured evidence collection across multiple system-level sources, correlated by time proximity, unified under one schema — built end-to-end as a functioning tool rather than evaluated only against static forensic datasets.

The Timeline Engine included here is intentionally lightweight: time-window clustering with a simple severity/source-count heuristic for flagging, not a configurable rules engine or a machine-learned scoring model. It demonstrates the correlation concept concretely rather than claiming a complete solution.

**Not included in this version**, and explicitly out of scope given project timeline: network/packet-level monitoring, MITRE ATT&CK technique mapping, a graphical dashboard, and the AI explanation/investigation layer. These are documented as future work below.

## Future Work

- **Richer correlation rules** — configurable, source-specific correlation logic in the Timeline Engine (e.g., explicitly linking a USB insertion to a subsequent file write on that same drive), rather than time-proximity alone
- **Network Monitoring & Packet Capture** — extend collection to network-layer activity
- **Threat Scoring & MITRE ATT&CK Mapping** — replace static severity labels with a weighted scoring model and map detections to known adversary techniques
- **Dashboard GUI** — a live visual interface in place of the current CLI report
- **AI Incident Explanation** — LLM-generated plain-English summaries of correlated timelines, grounded in stored evidence

---

## Known Limitations

- Login monitoring requires Administrator privileges and is Windows-only (`pywin32`); other collectors are more portable but haven't been tested cross-platform
- The file monitor manages its own database connection internally (for thread-safety reasons), while other collectors accept a shared connection — a minor architectural inconsistency, not a functional bug
- Severity levels are currently static per event type, not dynamically scored
- The Timeline Engine's clustering gap (10 seconds by default) and "interesting" threshold (3+ sources) are fixed constants, not yet exposed through configuration