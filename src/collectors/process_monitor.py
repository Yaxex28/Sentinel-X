import psutil
from core.models import Event
import time
from storage.repository import insert_event

def take_snapshot():

    snapshot = {}
    for proc in psutil.process_iter(['pid','name']):
        snapshot[proc.info['pid']] = proc.info['name']

    return snapshot
def detect_changes(old_snapshot: dict, new_snapshot: dict):
    """Compare two snapshots, return (new_pids, terminated_pids)."""
    new_pids = new_snapshot.keys() - old_snapshot.keys()
    terminated_pids = old_snapshot.keys() - new_snapshot.keys()
    return new_pids, terminated_pids

def filter_ignored(pids: set, snapshot: dict, ignored_list: list) -> set:
    """Remove PIDs whose process name is in the ignore list"""
    filtered = set()
    for pid in pids:
        name = snapshot.get(pid)
        if name not in ignored_list:
            filtered.add(pid)
    return filtered        

def build_events(new_pids:set,snapshot:dict,host:str) -> list:
    """build event objects for each new process PID."""
    events = []
    for pid in new_pids:
        name = snapshot.get(pid)
        event = Event(
            host = host,
            source = "process_monitor",
            event_type = "process_started",
            severity = "low",
            description = f"New process spawned: {name} (PID {pid})",
            raw_data = {"pid": pid, "name": name}
        )
        events.append(event)
    return events

def run_process_monitor(conn,host:str,ignore_list: list,poll_interval_seconds:int,max_iteration : int = None):    
    snap1 = take_snapshot()
    count = 0

    while True:
        count += 1
        time.sleep(poll_interval_seconds)
        snap2 = take_snapshot()

        new_pids, terminated_pids = detect_changes(snap1, snap2)
        filtered_pids = filter_ignored(new_pids, snap2, ignore_list)
        events = build_events(filtered_pids, snap2, host)

        for event in events:
            insert_event(conn,event)
            print(f"[+] {event.description}")

        snap1 = snap2    
        if max_iteration is not None and count >= max_iteration:
            break