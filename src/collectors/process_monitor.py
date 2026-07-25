import psutil
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
