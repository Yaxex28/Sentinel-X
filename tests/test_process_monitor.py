from collectors.process_monitor import detect_changes, filter_ignored, build_events, build_stopped_events

def test_detect_changes_finds_new_and_terminated():
    old = {1: "a.exe", 2: "b.exe"}
    new = {2: "b.exe", 3: "c.exe"}
    new_pids, terminated_pids = detect_changes(old, new)
    assert new_pids == {3}
    assert terminated_pids == {1}

def test_filter_ignored_skips_process():
    snapshot = {1: "a.exe", 2: "b.exe"}
    pids = {1, 2}
    filtered = filter_ignored(pids, snapshot, ["a.exe"])
    assert filtered == {2}

def test_build_events_creates_process_started():
    snapshot = {1: "c.exe"}
    events = build_events({1}, snapshot, "host1")
    assert len(events) == 1
    assert events[0].event_type == "process_started"
    assert "c.exe" in events[0].description
    assert events[0].raw_data["pid"] == 1

def test_build_stopped_events_creates_process_stopped():
    old_snapshot = {1: "a.exe"}
    events = build_stopped_events({1}, old_snapshot, "host1")
    assert len(events) == 1
    assert events[0].event_type == "process_stopped"
    assert "a.exe" in events[0].description
    assert events[0].raw_data["pid"] == 1
