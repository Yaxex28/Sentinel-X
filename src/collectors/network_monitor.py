import ipaddress
import os
import time
from collections import defaultdict
import psutil

from core.models import Event
from storage.repository import insert_event


class NetworkMonitorStats:
    """Tracks connection counts and timestamps to detect beaconing/volume."""
    def __init__(self):
        # Key: (name, remote_ip, remote_port) -> list of timestamps
        self.history = defaultdict(list)
        self.connection_counts = defaultdict(int)

    def record_connection(self, process_name, remote_ip, remote_port, timestamp):
        key = (process_name, remote_ip, remote_port)
        self.history[key].append(timestamp)
        self.connection_counts[key] += 1

    def is_beaconing(self, key, threshold_seconds=10, count=3) -> bool:
        """Check if connections occur at regular intervals (beaconing)."""
        times = self.history.get(key, [])
        if len(times) < count:
            return False

        recent = times[-count:]
        intervals = [recent[i] - recent[i-1] for i in range(1, len(recent))]

        # If intervals are close to threshold_seconds (within 3s tolerance)
        return all(abs(interval - threshold_seconds) < 3 for interval in intervals)


def take_snapshot() -> list:
    """Return the machine's current inet connections as plain dicts."""
    snapshot = []
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError):
        return snapshot
    for c in connections:
        local = c.laddr
        remote = c.raddr
        snapshot.append({
            "pid": c.pid,
            "status": c.status,
            "local_port": local.port if local else None,
            "remote_ip": remote.ip if remote else None,
            "remote_port": remote.port if remote else None,
        })
    return snapshot


def make_info_lookup():
    """Return a pid -> (name, exe) function with a cache that lives for one poll."""
    cache = {}

    def info_for(pid):
        if not pid:
            return "unknown", None
        if pid not in cache:
            try:
                p = psutil.Process(pid)
                cache[pid] = (p.name(), p.exe())
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                try:
                    cache[pid] = (psutil.Process(pid).name(), None)
                except:
                    cache[pid] = ("unknown", None)
        return cache[pid]

    return info_for


def is_loopback(ip) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def is_verified_system_process(name, exe_path):
    """Return True if the process is a known Windows system process in its correct folder."""
    if not exe_path:
        return False

    norm_path = os.path.normpath(exe_path)
    folder = os.path.dirname(norm_path)

    sys32 = os.path.normpath(r"C:\Windows\System32")
    syswow64 = os.path.normpath(r"C:\Windows\SysWOW64")
    defender = os.path.normpath(r"C:\ProgramData\Microsoft\Windows Defender\Platform")

    verified_rules = {
        "svchost.exe": [sys32, syswow64],
        "MpDefenderCoreService.exe": [defender],
        "lsass.exe": [sys32],
        "services.exe": [sys32],
        "SearchIndexer.exe": [sys32],
    }

    if name not in verified_rules:
        return False

    allowed_folders = verified_rules[name]
    for allowed in allowed_folders:
        if name == "MpDefenderCoreService.exe":
            if os.path.normcase(folder).startswith(os.path.normcase(allowed)):
                return True
        else:
            if os.path.normcase(folder) == os.path.normcase(allowed):
                return True
    return False


def find_new(snapshot, seen_destinations, seen_listeners, get_info,
             ignore_processes=(), suspicious_ports=(), stats=None, current_time=None):
    """Return (new_destinations, new_listeners) and record them in the seen sets."""
    new_destinations = []
    new_listeners = []
    current_time = current_time or time.time()

    for c in snapshot:
        outbound = (
            c["status"] == "ESTABLISHED"
            and c["remote_ip"]
            and not is_loopback(c["remote_ip"])
        )
        listening = c["status"] == "LISTEN" and c["local_port"] is not None
        if not (outbound or listening):
            continue

        name, exe_path = get_info(c["pid"])

        if name in ignore_processes:
            continue

        if outbound:
            is_verified = is_verified_system_process(name, exe_path)
            is_suspicious = c["remote_port"] in suspicious_ports

            if is_verified and not is_suspicious:
                continue

            key = (name, c["remote_ip"], c["remote_port"])
            if stats:
                stats.record_connection(name, c["remote_ip"], c["remote_port"], current_time)

            if key not in seen_destinations:
                seen_destinations.add(key)
                new_destinations.append(key)
        else:
            key = (name, c["local_port"])
            if key not in seen_listeners:
                seen_listeners.add(key)
                new_listeners.append(key)
    return new_destinations, new_listeners


def build_network_events(new_destinations, new_listeners, host, suspicious_ports=(), stats=None):
    events = []
    for name, ip, port in new_destinations:
        if port in suspicious_ports:
            event_type = "network_suspicious_port"
            severity = "medium"
            description = "Connection to commonly abused port: " + name + " -> " + ip + ":" + str(port)
        else:
            event_type = "network_connection_new"
            severity = "low"
            description = "New destination: " + name + " -> " + ip + ":" + str(port)

        # Check beaconing if stats provided
        if stats and stats.is_beaconing((name, ip, port)):
            event_type = "network_beaconing"
            severity = "medium"
            description = f"Regular connection interval (beaconing) detected: {name} -> {ip}:{port}"

        events.append(Event(
            host=host, source="network_monitor", event_type=event_type,
            severity=severity, description=description,
            raw_data={"process": name, "remote_ip": ip, "remote_port": port, "connection_count": stats.connection_counts.get((name, ip, port), 1) if stats else 1},
        ))

    for name, port in new_listeners:
        events.append(Event(
            host=host, source="network_monitor", event_type="listening_port_opened",
            severity="low", description="New listening port: " + name + " on " + str(port),
            raw_data={"process": name, "port": port},
        ))
    return events


def run_network_monitor(conn, host, poll_interval_seconds=5, suspicious_ports=(),
                        ignore_processes=(), max_iterations=None):
    """Poll connections; record destinations and listeners not seen before this session."""
    seen_destinations = set()
    seen_listeners = set()
    stats = NetworkMonitorStats()

    find_new(take_snapshot(), seen_destinations, seen_listeners, make_info_lookup(),
             ignore_processes, suspicious_ports, stats)

    count = 0
    while True:
        count += 1
        time.sleep(poll_interval_seconds)
        new_destinations, new_listeners = find_new(
            take_snapshot(), seen_destinations, seen_listeners, make_info_lookup(),
            ignore_processes, suspicious_ports, stats, time.time()
        )
        for event in build_network_events(new_destinations, new_listeners, host, suspicious_ports, stats):
            insert_event(conn, event)
            print("[+] " + event.description)
        if max_iterations is not None and count >= max_iterations:
            break
