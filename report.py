import sys
from collections import Counter
sys.path.insert(0, "src")

from storage.database import init_db
from storage.repository import query_events
from engine.timeline_engine import cluster_events, summarize_cluster, is_interesting


def generate_report(db_path: str):
    conn = init_db(db_path)
    events = query_events(conn)

    print("=" * 60)
    print("SENTINEL-X INCIDENT REPORT")
    print("=" * 60)
    print(f"Total events collected: {len(events)}\n")

    # Column indices, matching the table schema:
    # 0=id, 1=timestamp, 2=host, 3=source, 4=event_type, 5=severity, 6=description, 7=raw_data

    by_source = Counter(row[3] for row in events)
    by_severity = Counter(row[5] for row in events)

    print("-- Events by Source --")
    for source, count in by_source.most_common():
        print(f"  {source:20s} {count}")

    print("\n-- Events by Severity --")
    for severity, count in by_severity.most_common():
        print(f"  {severity:10s} {count}")

    high_severity = [row for row in events if row[5] in ("high", "medium")]
    print(f"\n-- High/Medium Severity Alerts ({len(high_severity)}) --")
    for row in sorted(high_severity, key=lambda r: r[1]):
        print(f"  [{row[1]}] {row[3]:16s} {row[6]}")

    sorted_events = sorted(events, key=lambda r: r[1])
    clusters = cluster_events(sorted_events, gap_seconds=10)

    print(f"\n-- Activity Clusters ({len(clusters)} total) --")
    interesting_count = 0
    for cluster in clusters:
        summary = summarize_cluster(cluster)
        flagged = is_interesting(summary)
        if flagged:
            interesting_count += 1
        flag_label = "  [FLAGGED]" if flagged else ""
        print(f"  {summary['start']} to {summary['end']} | {summary['event_count']} events | sources: {summary['sources_involved']}{flag_label}")

    print(f"\n{interesting_count} of {len(clusters)} clusters flagged as noteworthy.")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    generate_report("data/sentinel.db")