import win32evtlog
from core.models import Event

failed_login_times = []  # tracks recent failure timestamps

last_processed_time = None


def check_brute_force(new_failure_time, window_seconds=60, threshold=5) -> bool:
    """Track failed login timestamps, return True if threshold is exceeded within the window."""
    failed_login_times.append(new_failure_time)

    cutoff = new_failure_time - window_seconds
    while failed_login_times and failed_login_times[0] < cutoff:
        failed_login_times.pop(0)

    return len(failed_login_times) >= threshold


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
                new_events.append((real_id, event.TimeGenerated))
    finally:
        win32evtlog.CloseEventLog(handle)

    if new_events:
        last_processed_time = max(t for _, t in new_events)

    return new_events


def build_login_events(login_events: list, host: str) -> list:
    """Turn (event_id, timestamp) tuples into Event objects, oldest first.

    Emits one Event per login attempt, plus an extra high-severity
    brute_force_detected Event whenever a failure trips the sliding window.
    """
    events = []
    ordered = sorted(login_events, key=lambda p: p[1])

    for event_id, timestamp in ordered:
        if event_id == 4624:
            event_type = "login_success"
            severity = "low"
        elif event_id == 4625:
            event_type = "login_failure"
            severity = "medium"
        else:
            continue

        event = Event(
            host=host,
            source="login_monitor",
            event_type=event_type,
            severity=severity,
            description=f"{event_type} detected: event_id={event_id}",
            raw_data={"event_id": event_id, "time": str(timestamp)},
        )
        events.append(event)

        if event_type == "login_failure":
            time_value = timestamp.timestamp() if hasattr(timestamp, "timestamp") else timestamp
            if check_brute_force(time_value):
                alert = Event(
                    host=host,
                    source="login_monitor",
                    event_type="brute_force_detected",
                    severity="high",
                    description=f"Brute-force login attack detected on {host}",
                    raw_data={"event_id": event_id, "time": str(timestamp)},
                )
                events.append(alert)

    return events