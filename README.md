# Sentinel-X

**A lightweight, real-time host-based intrusion detection and event-correlation platform.**
Built as a B.Tech minor project (Information and Cyber Security).

Sentinel-X watches a single Windows machine through four independent collectors, stores everything in one structured event format, correlates activity across sources by time, scores it, tags it with MITRE ATT&CK techniques where defensible, and prints an incident report.

---

## Features

| Collector | Watches | Method |
|---|---|---|
| Process Monitor | New processes | `psutil` snapshots, set-difference, configurable ignore list |
| File Integrity Monitor | File create/modify/delete | `watchdog` OS notifications, debouncing, SHA-256 verification |
| USB Detector | Drive insertion | Drive-letter snapshot diffing |
| Login Monitor | Windows logon events 4624/4625 | `pywin32`, sliding-window brute-force detection (5 failures / 60 s) |

**Analytics layer**
- **Timeline Engine** — clusters events by time gap (10 s, measured from the most recent clustered event) and flags a cluster if it contains a medium/high severity event or involves 3+ distinct collectors.
- **Threat Scoring** — per-event-type baseline score (1 to 9), multiplied by 1.5 inside a flagged cluster.
- **MITRE ATT&CK tagging** — brute force (T1110), removable media (T1091), file deletion (T1070.004), each labelled with an honest confidence level. Routine activity is intentionally left unmapped.
- **HTML incident report and automated summaries** — `make_report_html.py` renders a self-contained page; every piece of event text is HTML-escaped. Each flagged cluster gets a short template-based summary that cites events by label ([E1], [E2]...) and states why the cluster was flagged. This is not AI-generated; a language-model adapter can be plugged into the same function, and its output is rejected if it cites an event that does not exist.

---

## Architecture

```
Collectors (process / file / usb / login)
        |  emit Event objects only
        v
SQLite storage (parameterized queries only)
        |
        v
Timeline Engine -> Threat Scoring -> ATT&CK tagging -> CLI report
```

Collectors never touch storage or analysis logic; every collector emits the same `Event` schema (id, timestamp, host, source, event_type, severity, description, raw_data).

```
src/
  core/        config.py, exceptions.py, logger.py, models.py
  collectors/  process_monitor.py, file_monitor.py, usb_monitor.py, login_monitor.py
  engine/      timeline_engine.py, threat_scoring.py, attack_mapping.py
  storage/     database.py, repository.py
config/default.yaml
tests/         26 pytest tests
run_all.py     starts all collectors concurrently
report.py      generates the incident report
  reporting/   report_data.py, html_report.py
  ai/          explainer.py
make_report_html.py   writes reports/incident_report.html
```

**Security decisions**
- Fail-closed YAML configuration: the program refuses to start on missing or malformed config.
- Parameterized SQL everywhere, so injection is not possible by construction.
- Each collector thread opens its own SQLite connection (SQLite connections cannot cross threads); the safety check was not disabled.

---

## Install

Windows, Python 3.10+.

```powershell
git clone https://github.com/Yaxex28/Sentinel-X.git
cd Sentinel-X
pip install -r requirements.txt
```

## Run

Open PowerShell **as Administrator** (required to read the Windows Security log).

```powershell
python run_all.py      # start all four collectors; Ctrl+C to stop
python report.py       # print the incident report
python -m pytest -v    # run the test suite
python make_report_html.py   # writes reports/incident_report.html
python run_dashboard.py   # run from an Administrator PowerShell; start/stop monitoring from the page
```

To generate demo activity: open a few programs, create/edit/delete a file in `watch_test/`, plug in a USB drive.

## Configuration

`config/default.yaml` drives poll interval, process ignore list and watched paths; `run_all.py` reads it at startup.

---

## Testing

34 automated tests cover config validation, storage and filtered queries (in-memory SQLite), file hashing and debouncing, USB diffing, brute-force detection (including a boundary test at the window edge), clustering and flagging, scoring, and ATT&CK mapping...scoring, ATT&CK mapping, report data, HTML escaping and the explainer’s citation checks.

## Results (live runs on the development machine)

**Run A: process, file, USB and login activity, no brute-force attempt.** 57 events (40 process, 9 login, 6 file, 2 USB) formed 6 clusters. One was flagged: a 15-event cluster combining login, process and USB activity, where the USB events scored 7.5 after the correlation multiplier.

**Run B: deliberate activity** (file create/edit/delete, USB insertion, six wrong-password attempts). 61 events (42 process, 10 login, 7 file, 2 USB; 53 low, 7 medium, 1 high) formed 4 clusters, all flagged because each contained a deliberate action. The highest-scored event was the brute-force alert (13.5 = baseline 9 x 1.5), followed by the USB insertions (7.5). The ATT&CK section reported T1110, T1091 and T1070.004.

## Positioning and limitations

Sentinel-X does not claim algorithmic novelty. Correlating events and generating incident narratives is an active research area (for example GenDFIR, which uses retrieval-augmented LLMs on offline forensic data). Sentinel-X is a working, live, single-machine implementation of the core correlation idea.

- Windows only; login monitoring needs Administrator rights.
- Scoring constants (10 s gap, 1.5x multiplier, 3-source threshold) are reasoned defaults, not tuned on labelled attack data, so no precision/recall figures are reported.
- ATT&CK coverage is intentionally small; most mappings are low-confidence indicators.
- Event timestamps record when the collector processed an event, which can lag the real Windows event time by up to one poll interval (the real time is kept in `raw_data`, and brute-force detection uses it).
- The fixed 10-second clustering gap is a hard boundary: in Run B, the failed logins and the brute-force alert were split across two clusters because the gap was exceeded by 0.03 seconds.
- Successful logins count as a source toward the "3+ sources" flagging rule, so a busy session can flag most clusters.
- Not included: network/packet monitoring, a graphical dashboard, and a connected language model (the explainer is template-based for now).

## Future work

Network monitoring, labelled-data evaluation of the scoring constants, a dashboard, and an LLM layer that explains flagged clusters from stored evidence.