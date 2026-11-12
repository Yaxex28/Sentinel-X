from collectors.usb_monitor import detect_usb_changes, build_usb_events

def test_detect_usb_changes_finds_inserted_and_removed():
    old_drives = {"C", "D"}
    new_drives = {"C", "D", "E"}
    inserted, removed = detect_usb_changes(old_drives, new_drives)
    assert inserted == {"E"}
    assert removed == set()

def test_detect_usb_changes_finds_removed():
    old_drives = {"C", "D", "E"}
    new_drives = {"C", "D"}
    inserted, removed = detect_usb_changes(old_drives, new_drives)
    assert inserted == set()
    assert removed == {"E"}

def test_build_usb_events_creates_usb_removed_event():
    events = build_usb_events(set(), {"E"}, "host1")
    assert len(events) == 1
    assert events[0].event_type == "usb_removed"
    assert events[0].severity == "low"
    assert "E:\\" in events[0].description
    assert events[0].raw_data["drive"] == "E"


    