from datetime import datetime


def event_gap_seconds(event_a, event_b) -> float:
    """Compute the time gap in seconds between two event rows."""
    time_a = datetime.fromisoformat(event_a[1])
    time_b = datetime.fromisoformat(event_b[1])
    return (time_b - time_a).total_seconds()


def cluster_events(events: list, gap_seconds: int = 10) -> list:
    """
    Group a chronologically-sorted list of events into clusters,
    where consecutive events within `gap_seconds` of each other
    belong to the same cluster.
    """
    if not events:
        return []

    clusters = []
    current_cluster = [events[0]]

    for event in events[1:]:
        previous_event = current_cluster[-1]
        gap = event_gap_seconds(previous_event, event)

        if gap <= gap_seconds:
            current_cluster.append(event)
        else:
            clusters.append(current_cluster)
            current_cluster = [event]

    clusters.append(current_cluster)
    return clusters


def summarize_cluster(cluster: list) -> dict:
    """Produce a quick summary of a cluster: time span, sources involved, event count."""
    start_time = cluster[0][1]
    end_time = cluster[-1][1]
    sources = sorted(set(row[3] for row in cluster))
    severities = sorted(set(row[5] for row in cluster))
    return {
        "start": start_time,
        "end": end_time,
        "event_count": len(cluster),
        "sources_involved": sources,
        "severities": severities,
    }

def is_interesting(summary: dict, min_sources: int = 3) -> bool:
    """A cluster is interesting if it has elevated severity or involves many sources."""
    has_elevated_severity = any(s in ("medium", "high") for s in summary["severities"])
    has_many_sources = len(summary["sources_involved"]) >= min_sources
    return has_elevated_severity or has_many_sources