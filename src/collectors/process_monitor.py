import psutil
from core.models import Event
import time
from storage.repository import insert_event
import os

CRITICAL_SYSTEM_PROCESSES = {"svchost.exe", "lsass.exe", "winlogon.exe", "services.exe", "csrss.exe", "explorer.exe"}
SYSTEM_DIR = r"C:\Windows\System32".lower()

def is_masquerading(name, exe_path):
    if name not in CRITICAL_SYSTEM_PROCESSES:
        return False
    if exe_path is None:
        return False

    exe_path_lower = exe_path.lower()
    return not exe_path_lower.startswith(SYSTEM_DIR) and not exe_path_lower.startswith(r"c:\windows")

def get_proc_name_and_exe(proc_info):
    if isinstance(proc_info, dict):
        return proc_info.get('name'), proc_info.get('exe')
    return proc_info, None

def take_snapshot():
    snapshot = {}
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            snapshot[proc.info['pid']] = {
                'name': proc.info.get('name'),
                'exe': proc.info.get('exe')
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            snapshot[proc.info['pid']] = {'name': proc.info.get('name'), 'exe': None}
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
        proc_info = snapshot.get(pid)
        name, _ = get_proc_name_and_exe(proc_info)
        if name not in ignored_list:
            filtered.add(pid)
    return filtered

def build_events(new_pids: set, snapshot: dict, host: str) -> list:
    """Build event objects for each new process PID."""
    events = []
    for pid in new_pids:
        proc_info = snapshot.get(pid)
        name, exe_path = get_proc_name_and_exe(proc_info)
        name = name or 'unknown'

        event = Event(
            host=host,
            source="process_monitor",
            event_type="process_started",
            severity="low",
            description=f"New process spawned: {name} (PID {pid})",
            raw_data={"pid": pid, "name": name, "exe": exe_path}
        )
        events.append(event)

        if is_masquerading(name, exe_path):
            alert = Event(
                host=host,
                source="process_monitor",
                event_type="process_masquerading",
                severity="medium",
                description=f"Masquerading detected: {name} running from unexpected path {exe_path}",
                raw_data={"pid": pid, "name": name, "exe": exe_path}
            )
            events.append(alert)

    return events

def build_stopped_events(terminated_pids: set, snapshot: dict, host: str) -> list:
    """Build event objects for each terminated process PID."""
    events = []
    for pid in terminated_pids:
        proc_info = snapshot.get(pid)
        name, _ = get_proc_name_and_exe(proc_info)
        name = name or 'unknown'

        event = Event(
            host=host,
            source="process_monitor",
            event_type="process_stopped",
            severity="low",
            description=f"Process stopped: {name} (PID {pid})",
            raw_data={"pid": pid, "name": name}
        )
        events.append(event)
    return events

def run_process_monitor(conn, host: str, ignore_list: list, poll_interval_seconds: int, max_iteration: int = None):
    snap1 = take_snapshot()
    count = 0

    while True:
        count += 1
        time.sleep(poll_interval_seconds)
        snap2 = take_snapshot()

        new_pids, terminated_pids = detect_changes(snap1, snap2)
        filtered_new = filter_ignored(new_pids, snap2, ignore_list)
        filtered_terminated = filter_ignored(terminated_pids, snap1, ignore_list)

        new_events = build_events(filtered_new, snap2, host)
        stopped_events = build_stopped_events(filtered_terminated, snap1, host)

        for event in new_events + stopped_events:
            insert_event(conn, event)
            print(f"[+] {event.description}")

        snap1 = snap2
        if max_iteration is not None and count >= max_iteration:
            break
