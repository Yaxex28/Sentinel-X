import sys
import json
from collections import Counter
sys.path.insert(0, "src")

from storage.database import init_db
from storage.repository import query_events


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

    print("\n-- Full Chronological Timeline (last 20) --")
    for row in sorted(events, key=lambda r: r[1])[-20:]:
        print(f"  [{row[1]}] ({row[5]:6s}) {row[6]}")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    generate_report("data/sentinel.db")