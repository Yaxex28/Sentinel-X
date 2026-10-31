from core.models import Event
from storage.database import init_db
from storage.repository import insert_event
from reporting.report_data import build_report_data


def test_report_data_counts_and_flags_usb_event():
    conn = init_db(":memory:")
    insert_event(conn, Event(
        host="h", source="usb_monitor", event_type="usb_inserted",
        severity="medium", description="USB drive inserted: E:\\",
        raw_data={"drive": "E"},
    ))
    data = build_report_data(conn)
    assert data["total"] == 1
    assert data["by_source"] == {"usb_monitor": 1}
    assert data["flagged_count"] == 1
    assert data["top_events"][0]["score"] == 7.5
    assert data["techniques"][0]["technique_id"] == "T1091"

def test_report_data_marks_indicators_seen_during_elevated_activity():
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
    data = build_report_data(conn)
    assert data["iocs"][0]["reasons"] == ["seen during elevated activity (cluster 1)"]