from collectors.usb_monitor import detect_usb_changes

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