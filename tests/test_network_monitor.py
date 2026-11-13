from collectors.network_monitor import find_new, build_network_events, is_loopback


def conn(status="ESTABLISHED", pid=10, remote_ip="93.184.216.34", remote_port=443, local_port=50000):
    return {"pid": pid, "status": status, "local_port": local_port,
            "remote_ip": remote_ip, "remote_port": remote_port}


def get_info(pid):
    return "app.exe", r"C:\Program Files\App\app.exe"


def test_loopback_connections_are_ignored():
    destinations, _ = find_new([conn(remote_ip="127.0.0.1")], set(), set(), get_info)
    assert destinations == []


def test_ipv6_loopback_is_recognised():
    assert is_loopback("::1") is True
    assert is_loopback("93.184.216.34") is False


def test_new_destination_is_reported_only_once():
    seen_destinations, seen_listeners = set(), set()
    first, _ = find_new([conn()], seen_destinations, seen_listeners, get_info)
    second, _ = find_new([conn(local_port=50001)], seen_destinations, seen_listeners, get_info)
    assert first == [("app.exe", "93.184.216.34", 443)]
    assert second == []


def test_new_listener_is_detected():
    listening = conn(status="LISTEN", remote_ip=None, remote_port=None, local_port=8080)
    _, listeners = find_new([listening], set(), set(), get_info)
    assert listeners == [("app.exe", 8080)]


def test_ignored_process_is_skipped():
    destinations, _ = find_new([conn()], set(), set(), get_info, ignore_processes=("app.exe",))
    assert destinations == []


def test_suspicious_port_becomes_medium_event():
    events = build_network_events([("evil.exe", "203.0.113.7", 4444)], [], "h", suspicious_ports=(4444,))
    assert events[0].event_type == "network_suspicious_port"
    assert events[0].severity == "medium"


def test_system_process_quieted_on_normal_port():
    # svchost in System32 on port 443 should be quieted
    snapshot = [conn(pid=20)]
    info = lambda pid: ("svchost.exe", r"C:\Windows\System32\svchost.exe")
    destinations, _ = find_new(snapshot, set(), set(), info)
    assert destinations == []


def test_system_process_not_quieted_on_suspicious_port():
    # svchost in System32 on port 4444 should NOT be quieted
    snapshot = [conn(pid=20, remote_port=4444)]
    info = lambda pid: ("svchost.exe", r"C:\Windows\System32\svchost.exe")
    destinations, _ = find_new(snapshot, set(), set(), info, suspicious_ports=(4444,))
    assert destinations == [("svchost.exe", "93.184.216.34", 4444)]


def test_system_process_not_quieted_in_wrong_folder():
    # svchost in Temp should NOT be quieted
    snapshot = [conn(pid=20)]
    info = lambda pid: ("svchost.exe", r"C:\Users\User\Temp\svchost.exe")
    destinations, _ = find_new(snapshot, set(), set(), info)
    assert destinations == [("svchost.exe", "93.184.216.34", 443)]


def test_system_process_not_quieted_in_lookalike_folder():
    # svchost in System32_fake should NOT be quieted
    snapshot = [conn(pid=20)]
    info = lambda pid: ("svchost.exe", r"C:\Windows\System32_fake\svchost.exe")
    destinations, _ = find_new(snapshot, set(), set(), info)
    assert destinations == [("svchost.exe", "93.184.216.34", 443)]


def test_system_process_not_quieted_with_path_trick():
    # svchost with .. trick resolving to Temp should NOT be quieted
    snapshot = [conn(pid=20)]
    # C:\Windows\System32\..\Temp\svchost.exe -> C:\Windows\Temp\svchost.exe
    info = lambda pid: ("svchost.exe", r"C:\Windows\System32\..\Temp\svchost.exe")
    destinations, _ = find_new(snapshot, set(), set(), info)
    assert destinations == [("svchost.exe", "93.184.216.34", 443)]


def test_system_process_visible_when_path_unreadable():
    # If path is None (unreadable), it stays visible
    snapshot = [conn(pid=20)]
    info = lambda pid: ("svchost.exe", None)
    destinations, _ = find_new(snapshot, set(), set(), info)
    assert destinations == [("svchost.exe", "93.184.216.34", 443)]


def test_mpdefender_quieted_in_platform_subfolder():
    # MpDefender in a versioned platform subfolder should be quieted
    snapshot = [conn(pid=30)]
    path = r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2205.7-0\MpDefenderCoreService.exe"
    info = lambda pid: ("MpDefenderCoreService.exe", path)
    destinations, _ = find_new(snapshot, set(), set(), info)
    assert destinations == []


def test_beaconing_detection():
    from collectors.network_monitor import NetworkMonitorStats
    stats = NetworkMonitorStats()
    key = ("malware.exe", "198.51.100.5", 443)

    # Simulate connection every 10 seconds
    t0 = 1000.0
    stats.record_connection("malware.exe", "198.51.100.5", 443, t0)
    stats.record_connection("malware.exe", "198.51.100.5", 443, t0 + 10.0)
    stats.record_connection("malware.exe", "198.51.100.5", 443, t0 + 20.0)

    assert stats.is_beaconing(key, threshold_seconds=10, count=3) is True
