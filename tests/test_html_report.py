from core.models import Event
from storage.database import init_db
from storage.repository import insert_event
from reporting.report_data import build_report_data
from reporting.html_report import render_html


def _html_for(description: str) -> str:
    conn = init_db(":memory:")
    insert_event(conn, Event(
        host="h", source="file_monitor", event_type="file_created",
        severity="low", description=description, raw_data={},
    ))
    return render_html(build_report_data(conn))


def test_html_report_contains_totals_and_title():
    html = _html_for("File created: notes.txt")
    assert "Sentinel-X Incident Report" in html
    assert "File created: notes.txt" in html


def test_html_report_escapes_attacker_controlled_text():
    html = _html_for("<script>alert(1)</script>")
    assert "<script>" not in html
    assert "&lt;script&gt;" in html

def test_html_report_escapes_explanation_text():
    conn = init_db(":memory:")
    insert_event(conn, Event(
        host="h", source="file_monitor", event_type="file_created",
        severity="low", description="a.txt", raw_data={},
    ))
    html = render_html(build_report_data(conn), explanations={1: "Seen <b>bold</b> [E1]"})
    assert "&lt;b&gt;bold&lt;/b&gt;" in html
    assert "<b>bold</b>" not in html

def test_html_report_escapes_indicator_context():
    conn = init_db(":memory:")
    insert_event(conn, Event(
        host="h", source="network_monitor", event_type="network_connection_new",
        severity="low", description="d",
        raw_data={"process": "<b>x</b>", "remote_ip": "93.184.216.34", "remote_port": 443},
    ))
    html = render_html(build_report_data(conn))
    assert "93.184.216.34" in html
    assert "&lt;b&gt;x&lt;/b&gt;" in html
    assert "<b>x</b>" not in html

def test_html_report_lists_notable_indicators_with_reason():
    conn = init_db(":memory:")
    insert_event(conn, Event(
        host="h", source="network_monitor", event_type="network_connection_new",
        severity="low", description="d",
        raw_data={"process": "a.exe", "remote_ip": "93.184.216.34", "remote_port": 443},
    ))
    insert_event(conn, Event(
        host="h", source="usb_monitor", event_type="usb_inserted",
        severity="medium", description="USB", raw_data={"drive": "E"},
    ))
    html = render_html(build_report_data(conn))
    assert "Notable (1)" in html
    assert "seen during elevated activity (cluster 1)" in html