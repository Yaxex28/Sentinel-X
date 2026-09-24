import win32evtlog

server ="localhost"
log_type = "Security"

handle = win32evtlog.OpenEventLog(server, log_type)

flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
events = win32evtlog.ReadEventLog(handle,flags,0)

found = 0
for _ in range(20):
    events = win32evtlog.ReadEventLog(handle, flags, 0)
    if not events:
        break
    for event in events:
        real_id = event.EventID & 0xFFFF
        if real_id in (4624, 4625):
            print(f"EventID: {real_id}, TimeGenerated: {event.TimeGenerated}")
            found += 1 
        if found >= 20:
            break
print(f"Found {found} LOGIN events.")