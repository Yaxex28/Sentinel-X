import sys
from collections import Counter
sys.path.insert(0, "src")

from storage.database import init_db
from storage.repository import query_events
from engine.timeline_engine import cluster_events, summarize_cluster, is_interesting
from engine.threat_scoring import score_event
from engine.attack_mapping import get_attack_tag

# Column indices, matching the events table schema:
# 0=id, 1=timestamp, 2=host, 3=source, 4=event_type, 5=severity, 6=description, 7=raw_data


def generate_report(db_path: str):
    conn = init_db(db_path)
    events = query_events(conn)

    print("=" * 66)
    print("SENTINEL-X INCIDENT REPORT")
    print("=" * 66)
    print(f"Total events collected: {len(events)}\n")

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

    # MITRE ATT&CK summary across all events
    technique_counts = Counter()
    for row in events:
        tag = get_attack_tag(row[4])
        if tag:
            key = (tag["technique_id"], tag["technique"], tag["tactic"])
            technique_counts[key] += 1

    print("\n-- MITRE ATT&CK Techniques Observed --")
    if not technique_counts:
        print("  (none)")
    for (tid, name, tactic), count in technique_counts.most_common():
        print(f"  {tid:10s} {name} ({tactic}): {count} event(s)")

    # Clustering and scoring
    sorted_events = sorted(events, key=lambda r: r[1])
    clusters = cluster_events(sorted_events, gap_seconds=10)

    print(f"\n-- Activity Clusters ({len(clusters)} total) --")
    interesting_count = 0
    scored_events = []

    for cluster in clusters:
        summary = summarize_cluster(cluster)
        flagged = is_interesting(summary)
        if flagged:
            interesting_count += 1
        flag_label = "  [FLAGGED]" if flagged else ""
        start = summary["start"]
        end = summary["end"]
        count = summary["event_count"]
        sources = summary["sources_involved"]
        print(f"{start} to {end} | {count} events | sources: {sources}{flag_label}")

        for event in cluster:
            score = score_event(event[4], cluster_is_interesting=flagged)
            scored_events.append((score, event[1], event[6]))
            tag = get_attack_tag(event[4])
            tag_label = ""
            if tag:
                tag_label = "  [" + tag["technique_id"] + " " + tag["technique"] + "]"
            print(f"    score={score:5.1f}   {event[6]}{tag_label}")

    print(f"\n{interesting_count} of {len(clusters)} clusters flagged as noteworthy.")

    print("\n-- Top 5 Highest-Scored Events --")
    for score, timestamp, description in sorted(scored_events, key=lambda s: s[0], reverse=True)[:5]:
        print(f"  {score:5.1f}  [{timestamp}] {description}")

    print("\n" + "=" * 66)


if __name__ == "__main__":
    generate_report("data/sentinel.db")