import sys
sys.path.insert(0, "src")

from storage.database import init_db
from reporting.report_data import build_report_data


def print_report(data: dict, show_all: bool = False):
    print("=" * 66)
    print("SENTINEL-X INCIDENT REPORT")
    print("=" * 66)
    print(f"Total events collected: {data['total']}\n")

    print("-- Events by Source --")
    for name, count in sorted(data["by_source"].items(), key=lambda kv: kv[1], reverse=True):
        print(f"  {name:20s} {count}")

    print("\n-- Events by Severity --")
    for name, count in sorted(data["by_severity"].items(), key=lambda kv: kv[1], reverse=True):
        print(f"  {name:10s} {count}")

    print(f"\n-- High/Medium Severity Alerts ({len(data['alerts'])}) --")
    for a in data["alerts"]:
        print(f"  [{a['timestamp']}] {a['source']:16s} {a['description']}")

    print("\n-- MITRE ATT&CK Techniques Observed --")
    if not data["techniques"]:
        print("  (none)")
    for t in data["techniques"]:
        print(f"  {t['technique_id']:10s} {t['technique']} ({t['tactic']}): {t['count']} event(s)")

    print(f"\n-- Activity Clusters ({len(data['clusters'])} total) --")
    for c in data["clusters"]:
        flag = "  [FLAGGED]" if c["flagged"] else ""
        print(f"{c['start']} to {c['end']} | {c['event_count']} events | sources: {c['sources']}{flag}")
        if c["flagged"] or show_all:
            for ev in c["events"]:
                tag = ""
                if ev["attack"]:
                    tag = "  [" + ev["attack"]["technique_id"] + " " + ev["attack"]["technique"] + "]"
                print(f"    score={ev['score']:5.1f}   {ev['description']}{tag}")

    print(f"\n{data['flagged_count']} of {len(data['clusters'])} clusters flagged as noteworthy.")

    print("\n-- Top 5 Highest-Scored Events --")
    for ev in data["top_events"]:
        print(f"  {ev['score']:5.1f}  [{ev['timestamp']}] {ev['description']}")

    print("\n" + "=" * 66)


if __name__ == "__main__":
    conn = init_db("data/sentinel.db")
    print_report(build_report_data(conn), show_all="--full" in sys.argv)