from datetime import datetime
from html import escape

CSS = """
body { font-family: Segoe UI, Arial, sans-serif; margin: 0; background: #f4f6fa; color: #14213d; }
header { background: #0b132b; color: #fff; padding: 24px 40px; }
header h1 { margin: 0 0 4px 0; font-size: 26px; }
header p { margin: 0; color: #b8c4d6; font-size: 14px; }
main { max-width: 1000px; margin: 0 auto; padding: 24px 40px 60px; }
h2 { margin-top: 36px; border-bottom: 2px solid #1c7c8c; padding-bottom: 6px; }
.stats { display: flex; gap: 16px; }
.stat { flex: 1; background: #fff; border-radius: 8px; padding: 16px; text-align: center; box-shadow: 0 1px 4px rgba(0,0,0,.1); }
.stat .n { font-size: 34px; font-weight: bold; color: #1c7c8c; }
.stat .l { font-size: 13px; color: #5c6b7a; }
table { width: 100%; border-collapse: collapse; background: #fff; margin-top: 10px; font-size: 14px; }
th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid #e3e8ef; }
th { background: #d9e2f3; }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
.badge { padding: 2px 8px; border-radius: 10px; font-size: 12px; font-weight: bold; color: #fff; background: #5c6b7a; }
.badge.low { background: #6c8ead; }
.badge.medium { background: #e09f3e; }
.badge.high { background: #c0392b; }
.badge.flagged { background: #c0392b; margin-left: 8px; }
.attack { background: #1c7c8c; color: #fff; padding: 1px 7px; border-radius: 8px; font-size: 12px; margin-left: 6px; }
details { background: #fff; border-radius: 8px; margin-top: 10px; padding: 10px 14px; box-shadow: 0 1px 4px rgba(0,0,0,.1); }
details.flagged { border-left: 5px solid #c0392b; }
summary { cursor: pointer; font-weight: bold; }
.bar { background: #1c7c8c; height: 12px; border-radius: 6px; }
table.counts th:nth-child(1), table.counts td:nth-child(1) { width: 30%; }
table.counts th:nth-child(2), table.counts td:nth-child(2) { width: 10%; text-align: right; }
.explain { background: #eef2f7; border-left: 4px solid #1c7c8c; padding: 8px 12px; margin: 10px 0; font-size: 14px; }
"""


def _e(value) -> str:
    """Escape anything that came from an event before it goes into HTML."""
    return escape(str(value))


def _badge(severity: str) -> str:
    css = severity if severity in ("low", "medium", "high") else "other"
    return '<span class="badge ' + css + '">' + _e(severity) + "</span>"


def _attack_tag(tag) -> str:
    if not tag:
        return ""
    return '<span class="attack">' + _e(tag["technique_id"]) + " " + _e(tag["technique"]) + "</span>"


def _count_table(title: str, counts: dict, total: int) -> str:
    rows = []
    for name, count in sorted(counts.items(), key=lambda kv: kv[1], reverse=True):
        pct = int(100 * count / total) if total else 0
        rows.append(
            "<tr><td>" + _e(name) + '</td><td class="num">' + str(count) + "</td>"
            '<td><div class="bar" style="width:' + str(pct) + '%"></div></td></tr>'
        )
        return ("<h3>" + _e(title) + '</h3><table class="counts"><tr><th>Name</th><th>Count</th><th></th></tr>'
            + "".join(rows) + "</table>")


def _cluster_html(index: int, cluster: dict, explanation=None, label="Automated summary") -> str:
    flagged = cluster["flagged"]
    badge = '<span class="badge flagged">FLAGGED</span>' if flagged else ""
    sources = ", ".join(_e(s) for s in cluster["sources"])
    rows = []
    for ev in cluster["events"]:
        rows.append(
            "<tr><td>" + _e(ev["timestamp"]) + "</td><td>" + _e(ev["source"]) + "</td><td>"
            + _e(ev["description"]) + _attack_tag(ev["attack"])
            + '</td><td class="num">' + format(ev["score"], ".1f") + "</td></tr>"
        )
    note = ""
    if explanation:
        note = '<p class="explain"><b>' + _e(label) + ":</b> " + _e(explanation) + "</p>"
    return (
        "<details" + (' class="flagged" open' if flagged else "") + "><summary>"
        + "Cluster " + str(index) + ": " + _e(cluster["start"]) + " to " + _e(cluster["end"])
        + " | " + str(cluster["event_count"]) + " events | " + sources + badge + "</summary>"
        + note
        + "<table><tr><th>Time</th><th>Source</th><th>Event</th><th>Score</th></tr>"
        + "".join(rows) + "</table></details>"
    )


def render_html(data: dict, explanations=None, explanation_label="Automated summary") -> str:
    explanations = explanations or {}
    """Turn the dict from build_report_data into one self-contained HTML page."""
    top_score = data["top_events"][0]["score"] if data["top_events"] else 0

    alerts = "".join(
        "<tr><td>" + _e(a["timestamp"]) + "</td><td>" + _e(a["source"]) + "</td><td>"
        + _e(a["description"]) + "</td></tr>" for a in data["alerts"]
    ) or '<tr><td colspan="3">None</td></tr>'

    techniques = "".join(
        "<tr><td>" + _e(t["technique_id"]) + "</td><td>" + _e(t["technique"]) + "</td><td>"
        + _e(t["tactic"]) + '</td><td class="num">' + str(t["count"]) + "</td></tr>"
        for t in data["techniques"]
    ) or '<tr><td colspan="4">None observed</td></tr>'

    top_events = "".join(
        '<tr><td class="num">' + format(e["score"], ".1f") + "</td><td>" + _e(e["timestamp"])
        + "</td><td>" + _e(e["description"]) + _attack_tag(e["attack"]) + "</td></tr>"
        for e in data["top_events"]
    )

    iocs = "".join(
        "<tr><td>" + _e(i["type"]) + "</td><td><code>" + _e(i["value"]) + '</code></td><td class="num">'
        + str(i["count"]) + "</td><td>" + _e(i["first_seen"]) + "</td><td>" + _e(i["last_seen"])
        + "</td><td>" + _e(", ".join(i["contexts"])) + "</td></tr>"
        for i in data["iocs"]
    ) or '<tr><td colspan="6">None extracted</td></tr>'

    clusters = "".join(
        _cluster_html(i, c, explanations.get(i), explanation_label)
        for i, c in enumerate(data["clusters"], start=1)
    )
    generated = datetime.now().strftime("%Y-%m-%d %H:%M")

    return (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        "<title>Sentinel-X Incident Report</title><style>" + CSS + "</style></head><body>"
        "<header><h1>Sentinel-X Incident Report</h1><p>Generated " + generated + "</p></header><main>"
        '<div class="stats">'
        '<div class="stat"><div class="n">' + str(data["total"]) + '</div><div class="l">events collected</div></div>'
        '<div class="stat"><div class="n">' + str(len(data["clusters"])) + '</div><div class="l">activity clusters</div></div>'
        '<div class="stat"><div class="n">' + str(data["flagged_count"]) + '</div><div class="l">flagged clusters</div></div>'
        '<div class="stat"><div class="n">' + format(top_score, ".1f") + '</div><div class="l">highest score</div></div>'
        "</div>"
        "<h2>Overview</h2>"
        + _count_table("Events by source", data["by_source"], data["total"])
        + _count_table("Events by severity", data["by_severity"], data["total"])
        + "<h2>Alerts (medium and high severity)</h2><table><tr><th>Time</th><th>Source</th><th>Description</th></tr>"
        + alerts + "</table>"
        + "<h2>MITRE ATT&amp;CK techniques observed</h2><table><tr><th>ID</th><th>Technique</th><th>Tactic</th><th>Events</th></tr>"
        + techniques + "</table>"
        + "<h2>Highest-scored events</h2><table><tr><th>Score</th><th>Time</th><th>Event</th></tr>"
        + top_events + "</table>"
        + "<h2>Indicators of compromise</h2><details><summary>Show " + str(len(data["iocs"]))
        + " indicators</summary><table><tr><th>Type</th><th>Value</th><th>Events</th><th>First seen</th><th>Last seen</th><th>Seen in</th></tr>"
        + iocs + "</table></details>"
        + "<h2>Activity clusters</h2>" + clusters
        + "</main></body></html>"
    )