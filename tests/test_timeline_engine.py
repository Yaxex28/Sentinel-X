from engine.timeline_engine import cluster_events, is_interesting

def test_cluster_events_groups_within_gap():
    events = [
        ("id1", "2026-01-01T00:00:00", "h", "s", "e", "low", "d", "{}"),
        ("id2", "2026-01-01T00:00:03", "h", "s", "e", "low", "d", "{}"),
        ("id3", "2026-01-01T00:01:00", "h", "s", "e", "low", "d", "{}"),
    ]
    clusters = cluster_events(events, gap_seconds=10)
    assert len(clusters) == 2
    assert len(clusters[0]) == 2
    assert len(clusters[1]) == 1

def test_is_interesting_flags_elevated_severity():
    summary = {"severities": ["medium"], "sources_involved": ["usb_monitor"]}
    assert is_interesting(summary) is True


def test_is_interesting_ignores_routine_low_severity():
    summary = {"severities": ["low"], "sources_involved": ["process_monitor", "login_monitor"]}
    assert is_interesting(summary) is False


def test_is_interesting_flags_many_sources_even_at_low_severity():
    summary = {"severities": ["low"], "sources_involved": ["a", "b", "c"]}
    assert is_interesting(summary) is True