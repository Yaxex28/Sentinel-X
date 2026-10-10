# Sentinel-X: Demo and Presentation Guide

## Before you present (do this the day before)

1. Open PowerShell **as Administrator**, `cd` to the project.
2. `python -m pytest -v` and confirm 26 passed.
3. `del data\sentinel.db` so the demo data is fresh.
4. Do one full rehearsal of the steps below, then delete the DB again right before presenting.
5. Keep a screenshot of a good `report.py` run as a backup in case the live demo misbehaves.

## 5-minute flow

**1. The problem (30 s).** Each monitoring tool writes its own log. Nobody ties them together, so an analyst sees noise, not a story.

**2. Architecture (60 s).** Four collectors, one shared Event schema, SQLite, then the Timeline Engine, scoring and ATT&CK tagging. Say the key design rule: collectors only emit events, they never know about storage or analysis.

**3. Live demo (2 min).**
- `python run_all.py`
- Open Notepad and Calculator.
- Create, edit and delete a file in `watch_test/`.
- Plug in a USB drive.
- Wait about 20 seconds, press `Ctrl+C`.
- `python report.py`

**4. Walk through the report (60 s).** Point at: total events, the clusters, the single `[FLAGGED]` cluster (login + process + USB together), the USB events scoring 7.5 instead of 5, and the ATT&CK section.

**5. Honest close (30 s).** Not novel research; a working live implementation. Limits: Windows only, reasoned constants not tuned on labelled data. Next step: dashboard and an LLM explanation layer.

## Questions you should be ready for

- **Why not machine learning?** No labelled data and a one-week window; rule-based logic is explainable and testable. ML is listed as future work.
- **How do you know the thresholds are right?** You don't claim to. They are reasoned defaults, checked by hand-traced tests, and not validated on labelled attack data.
- **Why does each thread open its own database connection?** SQLite connections cannot be shared across threads; disabling that check in a security tool was rejected.
- **Why parameterized queries?** SQL injection prevention by construction.
- **What does "flagged" mean?** A cluster with a medium/high event or 3+ distinct collectors within the window.
- **How is this different from GenDFIR?** That work uses an LLM on offline data; this runs live, without an LLM.
- **Why is login monitoring Administrator-only?** Windows restricts the Security log.