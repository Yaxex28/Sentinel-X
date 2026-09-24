import collectors.login_monitor as login_monitor
from collectors.login_monitor import build_login_events, check_brute_force


def setup_function():
    # check_brute_force uses a module-level list; reset it before every test
    login_monitor.failed_login_times.clear()


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
    # newest-first input, as process_login_events actually returns it
    login_events = [(4625, 3), (4625, 2), (4625, 1)]

    events = build_login_events(login_events, "pc")

    times = [e.raw_data["time"] for e in events if e.event_type == "login_failure"]
    assert times == ["1", "2", "3"]


def test_brute_force_alert_fires_at_threshold():
    # 5 failures within 60 seconds -> alert on the 5th
    login_events = [(4625, t) for t in [0, 10, 20, 30, 40]]

    events = build_login_events(login_events, "pc")

    alerts = [e for e in events if e.event_type == "brute_force_detected"]
    assert len(alerts) == 1
    assert alerts[0].severity == "high"


def test_no_alert_when_failures_are_spread_out():
    # 5 failures over 105 seconds -> should NOT trigger
    login_events = [(4625, t) for t in [0, 26, 52, 78, 105]]

    events = build_login_events(login_events, "pc")

    alerts = [e for e in events if e.event_type == "brute_force_detected"]
    assert len(alerts) == 0


def test_check_brute_force_boundary_exactly_at_window():
    # oldest failure exactly window_seconds old should have fallen out
    check_brute_force(0)
    check_brute_force(15)
    check_brute_force(30)
    check_brute_force(45)
    result = check_brute_force(60)  # cutoff = 0; time==0 is NOT < cutoff, so it stays

    assert result is True  # all 5 still within window at the boundary