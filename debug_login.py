import sys
sys.path.insert(0, "src")
import win32evtlog

handle = win32evtlog.OpenEventLog("localhost", "Security")
flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

total_scanned = 0
matches = 0
for _ in range(20):
    batch = win32evtlog.ReadEventLog(handle, flags, 0)
    if not batch:
        break
    for event in batch:
        total_scanned += 1
        real_id = event.EventID & 0xFFFF
        if real_id in (4624, 4625):
            matches += 1

print(f"Scanned {total_scanned} events, found {matches} login events")