from collections import Counter
from engine.ioc_extractor import extract_iocs, annotate_iocs
from storage.repository import query_events
from engine.timeline_engine import cluster_events, summarize_cluster, is_interesting
from engine.threat_scoring import score_event
from engine.attack_mapping import get_attack_tag

# Row columns: 0=id, 1=timestamp, 2=host, 3=source, 4=event_type,
# 5=severity, 6=description, 7=raw_data


def build_report_data(conn, gap_seconds: int = 10) -> dict:
    """Collect everything a report needs into one plain dict."""
    rows = query_events(conn)
    ordered = sorted(rows, key=lambda r: r[1])

    technique_counts = Counter()
    for row in rows:
        tag = get_attack_tag(row[4])
        if tag:
            key = (tag["technique_id"], tag["technique"], tag["tactic"])
            technique_counts[key] += 1

    clusters = []
    scored = []
    ioc_groups = []
    for number, group in enumerate(cluster_events(ordered, gap_seconds=gap_seconds), start=1):
        summary = summarize_cluster(group)
        ioc_groups.append((number, group, any(r[5] in ("medium", "high") for r in group)))        
        summary = summarize_cluster(group)
        flagged = is_interesting(summary)
        events = []
        for row in group:
            item = {
                "timestamp": row[1],
                "source": row[3],
                "event_type": row[4],
                "severity": row[5],
                "description": row[6],
                "score": score_event(row[4], cluster_is_interesting=flagged),
                "attack": get_attack_tag(row[4]),
            }
            events.append(item)
            scored.append(item)
        clusters.append({
            "start": summary["start"],
            "end": summary["end"],
            "event_count": summary["event_count"],
            "sources": summary["sources_involved"],
            "flagged": flagged,
            "events": events,
        })

    alerts = [
        {"timestamp": r[1], "source": r[3], "description": r[6]}
        for r in ordered if r[5] in ("medium", "high")
    ]
    techniques = [
        {"technique_id": tid, "technique": name, "tactic": tactic, "count": count}
        for (tid, name, tactic), count in technique_counts.most_common()
    ]

    return {
        "total": len(rows),
        "by_source": dict(Counter(r[3] for r in rows)),
        "by_severity": dict(Counter(r[5] for r in rows)),
        "alerts": alerts,
        "techniques": techniques,
        "clusters": clusters,
        "flagged_count": sum(1 for c in clusters if c["flagged"]),
        "top_events": sorted(scored, key=lambda e: e["score"], reverse=True)[:5],
        "iocs": annotate_iocs(extract_iocs(rows), ioc_groups),    }