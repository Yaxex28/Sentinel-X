import time
from storage.repository import insert_event
import string
import os
from core.models import Event
from collectors.process_monitor import take_snapshot
def get_drives() -> set:
    """return the set of currently mounted drive letter"""
    drives = set()
    for letter in string.ascii_uppercase:
        drive_path = f"{letter}:\\"
        if os.path.exists(drive_path):
            drives.add(letter)
    return drives

def detect_usb_changes(old_drives: set, new_drives: set):
    """compare two drive snapshots, return inserted, removed."""
    inserted = new_drives - old_drives
    removed = old_drives - new_drives
    return inserted,removed

def build_usb_events(inserted: set, host: str) -> list:
    """Build Event objects for each newly inserted USB drive."""
    events = []
    for drive in inserted:
        event = Event(
            host=host,
            source="usb_monitor",
            event_type="usb_inserted",
            severity="medium",
            description=f"USB drive inserted: {drive}:\\",
            raw_data={"drive": drive}
        )
        events.append(event)
    return events



def run_usb_monitor(conn, host: str, poll_interval_seconds: int, max_iterations: int = None):
    """Continuously monitor for USB drive insertions and log them as Events."""
    snap1 = get_drives()
    count = 0

    while True:
        count += 1
        time.sleep(poll_interval_seconds)
        snap2 = get_drives()

        inserted, removed = detect_usb_changes(snap1, snap2)
        events = build_usb_events(inserted, host)

        for event in events:
            insert_event(conn, event)
            print(f"[+] {event.description}")

        snap1 = snap2

        if max_iterations is not None and count >= max_iterations:
            break