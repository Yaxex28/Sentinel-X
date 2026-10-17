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