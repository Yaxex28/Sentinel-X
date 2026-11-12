import collectors.login_monitor as login_monitor
from collectors.login_monitor import build_login_events, check_brute_force
from datetime import datetime


def setup_function():
    login_monitor.clear_failed_logins()


def test_three_failures_become_three_login_failure_events():
    login_events = [(4625, 1), (4625, 2), (4625, 3)]

    events = build_login_events(login_events, "pc")

    assert len(events) == 3
    assert all(e.event_type == "login_failure" for e in events)


def test_success_event_has_correct_fields():
    login_events = [(4624, 1)]

    events = build_login_events(login_events, "pc")

    assert len(events) == 1
    assert events[0].event_type == "login_success"
    assert events[0].severity == "low"


def test_events_are_processed_oldest_first_even_if_input_is_newest_first():
    login_events = [(4625, 3), (4625, 2), (4625, 1)]

    events = build_login_events(login_events, "pc")

    times = [e.raw_data["time"] for e in events if e.event_type == "login_failure"]
    assert times == ["1", "2", "3"]


def test_brute_force_alert_fires_at_threshold():
    login_events = [(4625, t) for t in [0, 10, 20, 30, 40]]

    events = build_login_events(login_events, "pc")

    alerts = [e for e in events if e.event_type == "brute_force_detected"]
    assert len(alerts) == 1
    assert alerts[0].severity == "high"


def test_no_alert_when_failures_are_spread_out():
    login_events = [(4625, t) for t in [0, 26, 52, 78, 105]]

    events = build_login_events(login_events, "pc")

    alerts = [e for e in events if e.event_type == "brute_force_detected"]
    assert len(alerts) == 0


def test_check_brute_force_boundary_exactly_at_window():
    check_brute_force(0, source="test")
    check_brute_force(15, source="test")
    check_brute_force(30, source="test")
    check_brute_force(45, source="test")
    result = check_brute_force(60, source="test")

    assert result is True


def test_failures_from_different_sources_do_not_pool():
    # 3 failures from source A, 3 failures from source B (total 6, but split across sources -> no alert)
    login_events = [
        (4625, 0, "admin", "192.168.1.10"),
        (4625, 5, "admin", "192.168.1.10"),
        (4625, 10, "admin", "192.168.1.10"),
        (4625, 15, "admin", "192.168.1.20"),
        (4625, 20, "admin", "192.168.1.20"),
        (4625, 25, "admin", "192.168.1.20"),
    ]

    events = build_login_events(login_events, "pc")
    alerts = [e for e in events if e.event_type == "brute_force_detected"]
    assert len(alerts) == 0


def test_failures_from_single_source_alerts_independently():
    # 5 failures from source A, 3 failures from source B -> alert only for source A
    login_events = [
        (4625, 0, "admin", "192.168.1.10"),
        (4625, 10, "admin", "192.168.1.10"),
        (4625, 20, "admin", "192.168.1.10"),
        (4625, 30, "admin", "192.168.1.10"),
        (4625, 40, "admin", "192.168.1.10"),
        (4625, 15, "admin", "192.168.1.20"),
        (4625, 25, "admin", "192.168.1.20"),
    ]

    events = build_login_events(login_events, "pc")
    alerts = [e for e in events if e.event_type == "brute_force_detected"]
    assert len(alerts) == 1
    assert alerts[0].raw_data["source"] == "192.168.1.10"


def test_login_event_uses_real_datetime_timestamp():
    dt = datetime(2026, 6, 1, 12, 34, 56)
    login_events = [(4624, dt, "user1", "local")]
    events = build_login_events(login_events, "pc")
    assert len(events) == 1
    assert "2026-06-01T12:34:56" in events[0].timestamp

