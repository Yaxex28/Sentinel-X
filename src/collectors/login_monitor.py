import win32evtlog
from core.models import Event
import time
from storage.repository import insert_event

failed_login_times_by_source = {}  # tracks recent failure timestamps per source
last_processed_time = None

def clear_failed_logins():
    failed_login_times_by_source.clear()

def check_brute_force(new_failure_time, source="unknown", window_seconds=60, threshold=5) -> bool:
    """Track failed login timestamps per source, return True if threshold is exceeded within the window."""
    if source not in failed_login_times_by_source:
        failed_login_times_by_source[source] = []
    times = failed_login_times_by_source[source]
    times.append(new_failure_time)

    cutoff = new_failure_time - window_seconds
    while times and times[0] < cutoff:
        times.pop(0)

    return len(times) >= threshold

def parse_login_record(event):
    real_id = event.EventID & 0xFFFF
    timestamp = event.TimeGenerated
    inserts = getattr(event, "StringInserts", None) or []

    account = "unknown"
    source = "unknown"

    if real_id == 4625:
        if len(inserts) > 5:
            account = inserts[5]
        if len(inserts) > 14 and inserts[14] and inserts[14] != "-":
            source = inserts[14]
        elif len(inserts) > 12 and inserts[12] and inserts[12] != "-":
            source = inserts[12]
    elif real_id == 4624:
        if len(inserts) > 5:
            account = inserts[5]
        if len(inserts) > 15 and inserts[15] and inserts[15] != "-":
            source = inserts[15]
        elif len(inserts) > 11 and inserts[11] and inserts[11] != "-":
            source = inserts[11]

    return real_id, timestamp, account, source

def process_login_events(host: str):
    """Read new login events from the windows security log."""
    global last_processed_time
    handle = win32evtlog.OpenEventLog("localhost", "Security")
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    new_events = []
    try:
        for _ in range(20):
            batch = win32evtlog.ReadEventLog(handle, flags, 0)
            if not batch:
                break
            for event in batch:
                real_id = event.EventID & 0xFFFF
                if real_id not in (4624, 4625):
                    continue
                if last_processed_time is not None and event.TimeGenerated <= last_processed_time:
                    continue
                new_events.append(parse_login_record(event))
    finally:
        win32evtlog.CloseEventLog(handle)

    if new_events:
        last_processed_time = max(t for _, t, _, _ in new_events)

    return new_events

def build_login_events(login_events: list, host: str) -> list:
    """Turn login event tuples into Event objects, oldest first.

    Supports (event_id, timestamp) or (event_id, timestamp, account, source).
    """
    events = []
    ordered = sorted(login_events, key=lambda p: p[1])

    for item in ordered:
        if len(item) == 4:
            event_id, timestamp, account, source = item
        elif len(item) == 3:
            event_id, timestamp, account = item
            source = "unknown"
        else:
            event_id, timestamp = item
            account = "unknown"
            source = "unknown"

        if event_id == 4624:
            event_type = "login_success"
            severity = "low"
        elif event_id == 4625:
            event_type = "login_failure"
            severity = "medium"
        else:
            continue

        raw_data = {
            "event_id": event_id,
            "time": str(timestamp),
            "account": account,
            "source": source
        }

        event = Event(
            host=host,
            source="login_monitor",
            event_type=event_type,
            severity=severity,
            description=f"{event_type} detected: account={account}, source={source}",
            raw_data=raw_data,
        )
        events.append(event)

        if event_type == "login_failure":
            time_value = timestamp.timestamp() if hasattr(timestamp, "timestamp") else timestamp
            if check_brute_force(time_value, source=source):
                alert = Event(
                    host=host,
                    source="login_monitor",
                    event_type="brute_force_detected",
                    severity="high",
                    description=f"Brute-force login attack detected on {host} from source {source}",
                    raw_data=raw_data,
                )
                events.append(alert)

    return events

def run_login_monitor(conn, host: str, poll_interval_seconds: int = 5, max_iterations: int = None):
    """Continuously poll the Security log, build Events, and store them."""
    count = 0

    while True:
        raw_events = process_login_events(host)

        if raw_events:
            events = build_login_events(raw_events, host)
            for event in events:
                insert_event(conn, event)
                print(f"[+] {event.description}")

        time.sleep(poll_interval_seconds)

        count += 1
        if max_iterations is not None and count >= max_iterations:
            break
