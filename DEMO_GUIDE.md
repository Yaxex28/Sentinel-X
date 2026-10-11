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
- Press Win+L and enter a wrong password 6 times in a row, then sign back in (the brute-force rule needs 5 failures within 60 seconds).
- Wait about 20 seconds, press `Ctrl+C`.
- `python report.py`

**4. Walk through the report (60 s).** Point at: total events and the four sources, the brute-force alert scoring 13.5 at the top of the highest-scored list, the USB events scoring 7.5 instead of 5, the `[FLAGGED]` clusters, and the ATT&CK section (T1110, T1091, T1070.004).

**5. Honest close (30 s).** Not novel research; a working live implementation. Limits: Windows only, reasoned constants not tuned on labelled data. Next step: dashboard and an LLM explanation layer.

## Questions you should be ready for

- **Why not machine learning?** No labelled data and a one-week window; rule-based logic is explainable and testable. ML is listed as future work.
- **How do you know the thresholds are right?** You don't claim to. They are reasoned defaults, checked by hand-traced tests, and not validated on labelled attack data.
- **Why does each thread open its own database connection?** SQLite connections cannot be shared across threads; disabling that check in a security tool was rejected.
- **Why parameterized queries?** SQL injection prevention by construction.
- **Why is every cluster flagged in your demo?** Each cluster contained something deliberate: a USB insertion, failed logins or a file deletion. In the earlier run with less provocation, only 1 of 6 clusters was flagged. A successful login also counts as a source, which makes the 3-source rule easy to meet in a busy session; that is a known limitation.
- **Why were the failed logins split across two clusters?** The fixed 10-second gap was exceeded by 0.03 seconds. Tuning it on labelled data is future work.
- **What does "flagged" mean?** A cluster with a medium/high event or 3+ distinct collectors within the window.
- **How is this different from GenDFIR?** That work uses an LLM on offline data; this runs live, without an LLM.
- **Why is login monitoring Administrator-only?** Windows restricts the Security log.