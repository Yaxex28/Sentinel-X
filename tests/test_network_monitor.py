from collectors.network_monitor import find_new, build_network_events, is_loopback


def conn(status="ESTABLISHED", pid=10, remote_ip="93.184.216.34", remote_port=443, local_port=50000):
    return {"pid": pid, "status": status, "local_port": local_port,
            "remote_ip": remote_ip, "remote_port": remote_port}


def name_for(pid):
    return "app.exe"


def test_loopback_connections_are_ignored():
    destinations, _ = find_new([conn(remote_ip="127.0.0.1")], set(), set(), name_for)
    assert destinations == []


def test_ipv6_loopback_is_recognised():
    assert is_loopback("::1") is True
    assert is_loopback("93.184.216.34") is False


def test_new_destination_is_reported_only_once():
    seen_destinations, seen_listeners = set(), set()
    first, _ = find_new([conn()], seen_destinations, seen_listeners, name_for)
    second, _ = find_new([conn(local_port=50001)], seen_destinations, seen_listeners, name_for)
    assert first == [("app.exe", "93.184.216.34", 443)]
    assert second == []


def test_new_listener_is_detected():
    listening = conn(status="LISTEN", remote_ip=None, remote_port=None, local_port=8080)
    _, listeners = find_new([listening], set(), set(), name_for)
    assert listeners == [("app.exe", 8080)]


def test_ignored_process_is_skipped():
    destinations, _ = find_new([conn()], set(), set(), name_for, ignore_processes=("app.exe",))
    assert destinations == []


def test_suspicious_port_becomes_medium_event():
    events = build_network_events([("evil.exe", "203.0.113.7", 4444)], [], "h", suspicious_ports=(4444,))
    assert events[0].event_type == "network_suspicious_port"
    assert events[0].severity == "medium"
