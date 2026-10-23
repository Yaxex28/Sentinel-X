import ipaddress
import time

import psutil

from core.models import Event
from storage.repository import insert_event


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


def make_name_lookup():
    """Return a pid -> process name function with a cache that lives for one poll."""
    cache = {}

    def name_for(pid):
        if not pid:
            return "unknown"
        if pid not in cache:
            try:
                cache[pid] = psutil.Process(pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                cache[pid] = "unknown"
        return cache[pid]

    return name_for


def is_loopback(ip) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def find_new(snapshot, seen_destinations, seen_listeners, name_for, ignore_processes=()):
    """Return (new_destinations, new_listeners) and record them in the seen sets.

    A destination is (process, remote_ip, remote_port): reported the first time
    it appears, however many connections later use it. A listener is
    (process, local_port).
    """
    new_destinations = []
    new_listeners = []
    for c in snapshot:
        outbound = (
            c["status"] == "ESTABLISHED"
            and c["remote_ip"]
            and not is_loopback(c["remote_ip"])
        )
        listening = c["status"] == "LISTEN" and c["local_port"] is not None
        if not (outbound or listening):
            continue
        name = name_for(c["pid"])
        if name in ignore_processes:
            continue
        if outbound:
            key = (name, c["remote_ip"], c["remote_port"])
            if key not in seen_destinations:
                seen_destinations.add(key)
                new_destinations.append(key)
        else:
            key = (name, c["local_port"])
            if key not in seen_listeners:
                seen_listeners.add(key)
                new_listeners.append(key)
    return new_destinations, new_listeners


def build_network_events(new_destinations, new_listeners, host, suspicious_ports=()):
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
        events.append(Event(
            host=host, source="network_monitor", event_type=event_type,
            severity=severity, description=description,
            raw_data={"process": name, "remote_ip": ip, "remote_port": port},
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
    # Baseline: whatever is already connected when we start is not an event.
    find_new(take_snapshot(), seen_destinations, seen_listeners, make_name_lookup(), ignore_processes)

    count = 0
    while True:
        count += 1
        time.sleep(poll_interval_seconds)
        new_destinations, new_listeners = find_new(
            take_snapshot(), seen_destinations, seen_listeners, make_name_lookup(), ignore_processes
        )
        for event in build_network_events(new_destinations, new_listeners, host, suspicious_ports):
            insert_event(conn, event)
            print("[+] " + event.description)
        if max_iterations is not None and count >= max_iterations:
            break
